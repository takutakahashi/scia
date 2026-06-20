package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

type Injector struct {
	client  *http.Client
	secrets secrets.Store
	cache   sync.Map
}

func NewInjector(secretStore secrets.Store) *Injector {
	if secretStore == nil {
		secretStore = secrets.NoopStore{}
	}
	return &Injector{client: &http.Client{Timeout: 10 * time.Second}, secrets: secretStore}
}

func (i *Injector) Apply(ctx context.Context, r *http.Request, cfg *config.Config, ids []string) error {
	for _, id := range ids {
		cred, ok := config.CredentialByID(cfg, id)
		if !ok {
			return fmt.Errorf("credential %q not found", id)
		}
		if err := i.applyOne(ctx, r, cfg, cred); err != nil {
			return err
		}
	}
	return nil
}

func (i *Injector) applyOne(ctx context.Context, r *http.Request, cfg *config.Config, cred config.CredentialConfig) error {
	switch cred.Type {
	case "bearer":
		token := config.HeaderValueFromEnv(cred.Value)
		r.Header.Set("Authorization", "Bearer "+token)
	case "basic":
		username := config.HeaderValueFromEnv(cred.Params["username"])
		password := config.HeaderValueFromEnv(cred.Params["password"])
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	case "static-header":
		if cred.Header == "" {
			return fmt.Errorf("credential %q requires header", cred.ID)
		}
		r.Header.Set(cred.Header, config.HeaderValueFromEnv(cred.Value))
	case "oauth2-client-credentials":
		token, err := i.clientCredentialsToken(ctx, cred)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+token)
	case "google-oauth-refresh-token":
		token, err := i.googleRefreshToken(ctx, cfg, cred)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+token)
	case "notion-oauth-refresh-token":
		token, notionVersion, err := i.notionRefreshToken(ctx, cfg, cred)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+token)
		if r.Header.Get("Notion-Version") == "" {
			r.Header.Set("Notion-Version", notionVersion)
		}
	case "todoist-oauth-refresh-token":
		token, err := i.todoistRefreshToken(ctx, cfg, cred)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+token)
	case "slack-oauth-access-token":
		token, err := i.slackAccessToken(ctx, cfg, cred)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+token)
	default:
		return fmt.Errorf("unsupported credential type %q", cred.Type)
	}
	return nil
}

func (i *Injector) slackAccessToken(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	token, err := i.secretValue(ctx, cfg, cred, "access_token")
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", fmt.Errorf("credential %q requires access_token", cred.ID)
	}
	return token, nil
}

func (i *Injector) notionRefreshToken(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, string, error) {
	if value, ok := i.cache.Load(cred.ID); ok {
		token := value.(cachedToken)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.accessToken, i.notionVersion(cfg, cred), nil
		}
	}

	tokenURL := cred.Params["token_url"]
	tokenBrokerURL := config.HeaderValueFromEnv(cred.Params["token_broker_url"])
	notionCfg, hasNotionCfg := config.NotionOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasNotionCfg {
		tokenURL = notionCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = "https://api.notion.com/v1/oauth/token"
	}
	refreshToken, err := i.rotatingSecretValue(ctx, cfg, cred, "refresh_token")
	if err != nil {
		return "", "", err
	}
	if refreshToken == "" {
		return "", "", fmt.Errorf("credential %q requires refresh_token", cred.ID)
	}
	version := i.notionVersion(cfg, cred)
	if tokenBrokerURL != "" {
		token, rotatedRefreshToken, err := i.notionJSONToken(ctx, cred.ID, tokenBrokerURL, version, map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
		}, "", "", config.HeaderValueFromEnv(cred.Params["token_broker_token"]))
		if err != nil {
			return "", "", err
		}
		if rotatedRefreshToken != "" {
			if err := i.secrets.Put(ctx, config.CredentialUserID(cfg, cred), "refresh_token", rotatedRefreshToken); err != nil {
				return "", "", err
			}
		}
		return token, version, nil
	}
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	if clientID == "" && hasNotionCfg {
		var err error
		clientID, err = i.notionClientValue(ctx, notionCfg.ClientID, notionCfg.ClientIDSecretRef)
		if err != nil {
			return "", "", err
		}
	}
	clientSecret := config.HeaderValueFromEnv(cred.Params["client_secret"])
	if clientSecret == "" && hasNotionCfg {
		var err error
		clientSecret, err = i.notionClientValue(ctx, notionCfg.ClientSecret, notionCfg.ClientSecretRef)
		if err != nil {
			return "", "", err
		}
	}
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("credential %q requires client_id, client_secret, and refresh_token", cred.ID)
	}
	token, rotatedRefreshToken, err := i.notionJSONToken(ctx, cred.ID, tokenURL, version, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}, clientID, clientSecret, "")
	if err != nil {
		return "", "", err
	}
	if rotatedRefreshToken != "" {
		if err := i.secrets.Put(ctx, config.CredentialUserID(cfg, cred), "refresh_token", rotatedRefreshToken); err != nil {
			return "", "", err
		}
	}
	return token, version, nil
}

type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

func (i *Injector) clientCredentialsToken(ctx context.Context, cred config.CredentialConfig) (string, error) {
	if value, ok := i.cache.Load(cred.ID); ok {
		token := value.(cachedToken)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.accessToken, nil
		}
	}

	tokenURL := cred.Params["token_url"]
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	clientSecret := config.HeaderValueFromEnv(cred.Params["client_secret"])
	if tokenURL == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("credential %q requires token_url, client_id, and client_secret", cred.ID)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope := cred.Params["scope"]; scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := i.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("token endpoint returned %s", resp.Status)
	}

	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.AccessToken == "" {
		return "", errors.New("token endpoint response did not include access_token")
	}
	if body.TokenType != "" && !strings.EqualFold(body.TokenType, "bearer") {
		return "", fmt.Errorf("unsupported token_type %q", body.TokenType)
	}
	expiresIn := time.Duration(body.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}
	i.cache.Store(cred.ID, cachedToken{accessToken: body.AccessToken, expiresAt: time.Now().Add(expiresIn)})
	return body.AccessToken, nil
}

func (i *Injector) googleRefreshToken(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value, ok := i.cache.Load(cred.ID); ok {
		token := value.(cachedToken)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.accessToken, nil
		}
	}

	tokenURL := cred.Params["token_url"]
	tokenBrokerURL := config.HeaderValueFromEnv(cred.Params["token_broker_url"])
	googleCfg, hasGoogleCfg := config.GoogleOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasGoogleCfg {
		tokenURL = googleCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	if clientID == "" && hasGoogleCfg {
		var err error
		clientID, err = i.googleClientValue(ctx, googleCfg.ClientID, googleCfg.ClientIDSecretRef)
		if err != nil {
			return "", err
		}
	}
	clientSecret := config.HeaderValueFromEnv(cred.Params["client_secret"])
	if clientSecret == "" && hasGoogleCfg {
		var err error
		clientSecret, err = i.googleClientValue(ctx, googleCfg.ClientSecret, googleCfg.ClientSecretRef)
		if err != nil {
			return "", err
		}
	}
	refreshToken, err := i.secretValue(ctx, cfg, cred, "refresh_token")
	if err != nil {
		return "", err
	}
	if tokenBrokerURL != "" {
		if refreshToken == "" {
			return "", fmt.Errorf("credential %q requires refresh_token", cred.ID)
		}
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)
		if scope := cred.Params["scope"]; scope != "" {
			form.Set("scope", scope)
		}
		return i.formToken(ctx, cred.ID, tokenBrokerURL, form, config.HeaderValueFromEnv(cred.Params["token_broker_token"]))
	}
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return "", fmt.Errorf("credential %q requires client_id, client_secret, and refresh_token", cred.ID)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", refreshToken)
	return i.formToken(ctx, cred.ID, tokenURL, form, "")
}

func (i *Injector) todoistRefreshToken(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value, ok := i.cache.Load(cred.ID); ok {
		token := value.(cachedToken)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.accessToken, nil
		}
	}

	if accessToken, err := i.secretValue(ctx, cfg, cred, "access_token"); err != nil {
		return "", err
	} else if accessToken != "" {
		expiresIn := time.Duration(315360000) * time.Second
		i.cache.Store(cred.ID, cachedToken{accessToken: accessToken, expiresAt: time.Now().Add(expiresIn)})
		return accessToken, nil
	}

	tokenURL := cred.Params["token_url"]
	tokenBrokerURL := config.HeaderValueFromEnv(cred.Params["token_broker_url"])
	todoistCfg, hasTodoistCfg := config.TodoistOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasTodoistCfg {
		tokenURL = todoistCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = "https://api.todoist.com/oauth/access_token"
	}
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	if clientID == "" && hasTodoistCfg {
		var err error
		clientID, err = i.todoistClientValue(ctx, todoistCfg.ClientID, todoistCfg.ClientIDSecretRef)
		if err != nil {
			return "", err
		}
	}
	clientSecret := config.HeaderValueFromEnv(cred.Params["client_secret"])
	if clientSecret == "" && hasTodoistCfg {
		var err error
		clientSecret, err = i.todoistClientValue(ctx, todoistCfg.ClientSecret, todoistCfg.ClientSecretRef)
		if err != nil {
			return "", err
		}
	}
	refreshToken, err := i.secretValue(ctx, cfg, cred, "refresh_token")
	if err != nil {
		return "", err
	}
	if tokenBrokerURL != "" {
		if refreshToken == "" {
			return "", fmt.Errorf("credential %q requires refresh_token or access_token", cred.ID)
		}
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)
		if scope := cred.Params["scope"]; scope != "" {
			form.Set("scope", scope)
		}
		token, rotatedRefreshToken, err := i.formTokenWithRefresh(ctx, cred.ID, tokenBrokerURL, form, config.HeaderValueFromEnv(cred.Params["token_broker_token"]))
		if err != nil {
			return "", err
		}
		if rotatedRefreshToken != "" {
			if err := i.secrets.Put(ctx, config.CredentialUserID(cfg, cred), "refresh_token", rotatedRefreshToken); err != nil {
				return "", err
			}
		}
		return token, nil
	}
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return "", fmt.Errorf("credential %q requires client_id, client_secret, and refresh_token, or access_token", cred.ID)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", refreshToken)
	token, rotatedRefreshToken, err := i.formTokenWithRefresh(ctx, cred.ID, tokenURL, form, "")
	if err != nil {
		return "", err
	}
	if rotatedRefreshToken != "" {
		if err := i.secrets.Put(ctx, config.CredentialUserID(cfg, cred), "refresh_token", rotatedRefreshToken); err != nil {
			return "", err
		}
	}
	return token, nil
}

func (i *Injector) googleClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, i.secrets, secretRef)
}

func (i *Injector) todoistClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, i.secrets, secretRef)
}

func (i *Injector) notionClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, i.secrets, secretRef)
}

func (i *Injector) secretValue(ctx context.Context, cfg *config.Config, cred config.CredentialConfig, key string) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params[key]); value != "" {
		return value, nil
	}
	userID := config.CredentialUserID(cfg, cred)
	value, ok, err := i.secrets.Get(ctx, userID, key)
	if err != nil {
		return "", err
	}
	if ok {
		return value, nil
	}
	return "", nil
}

func (i *Injector) rotatingSecretValue(ctx context.Context, cfg *config.Config, cred config.CredentialConfig, key string) (string, error) {
	userID := config.CredentialUserID(cfg, cred)
	value, ok, err := i.secrets.Get(ctx, userID, key)
	if err != nil {
		return "", err
	}
	if ok {
		return value, nil
	}
	return config.HeaderValueFromEnv(cred.Params[key]), nil
}

func (i *Injector) formToken(ctx context.Context, credentialID, tokenURL string, form url.Values, bearerToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	return i.decodeAndCacheToken(credentialID, resp)
}

func (i *Injector) formTokenWithRefresh(ctx context.Context, credentialID, tokenURL string, form url.Values, bearerToken string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", "", err
	}
	if token.AccessToken == "" {
		return "", "", errors.New("token endpoint response did not include access_token")
	}
	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "bearer") {
		return "", "", fmt.Errorf("unsupported token_type %q", token.TokenType)
	}
	expiresIn := time.Duration(token.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}
	i.cache.Store(credentialID, cachedToken{accessToken: token.AccessToken, expiresAt: time.Now().Add(expiresIn)})
	return token.AccessToken, token.RefreshToken, nil
}

func (i *Injector) notionJSONToken(ctx context.Context, credentialID, tokenURL, notionVersion string, body map[string]string, clientID, clientSecret, bearerToken string) (string, string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(payload))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Notion-Version", notionVersion)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	} else {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", "", err
	}
	if token.AccessToken == "" {
		return "", "", errors.New("token endpoint response did not include access_token")
	}
	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "bearer") {
		return "", "", fmt.Errorf("unsupported token_type %q", token.TokenType)
	}
	expiresIn := time.Duration(token.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}
	i.cache.Store(credentialID, cachedToken{accessToken: token.AccessToken, expiresAt: time.Now().Add(expiresIn)})
	return token.AccessToken, token.RefreshToken, nil
}

func (i *Injector) notionVersion(cfg *config.Config, cred config.CredentialConfig) string {
	if version := cred.Params["notion_version"]; version != "" {
		return version
	}
	if notionCfg, ok := config.NotionOAuthConfigForCredential(cfg, cred.ID); ok && notionCfg.NotionVersion != "" {
		return notionCfg.NotionVersion
	}
	return "2026-03-11"
}

func (i *Injector) decodeAndCacheToken(credentialID string, resp *http.Response) (string, error) {
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.AccessToken == "" {
		return "", errors.New("token endpoint response did not include access_token")
	}
	if body.TokenType != "" && !strings.EqualFold(body.TokenType, "bearer") {
		return "", fmt.Errorf("unsupported token_type %q", body.TokenType)
	}
	expiresIn := time.Duration(body.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}
	i.cache.Store(credentialID, cachedToken{accessToken: body.AccessToken, expiresAt: time.Now().Add(expiresIn)})
	return body.AccessToken, nil
}
