package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
	"github.com/takutakahashi/scia/internal/serviceinfo"
)

type Injector struct {
	client  *http.Client
	secrets secrets.Store
	cache   sync.Map
	locks   sync.Map
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

func (i *Injector) ApplyServices(ctx context.Context, r *http.Request, cfg *config.Config, ids []string) error {
	for _, id := range ids {
		service, ok, err := i.serviceByID(ctx, cfg, id)
		if err != nil {
			return fmt.Errorf("service %q: %w", id, err)
		}
		if !ok {
			return fmt.Errorf("service %q not found", id)
		}
		rule, ok := serviceHostRule(service, r.URL.Host, r.URL.Path)
		if !ok {
			return fmt.Errorf("service %q does not match %s%s", id, r.URL.Host, r.URL.Path)
		}
		fields := map[string]string{}
		if service.OAuth != nil {
			var err error
			fields, err = i.genericOAuthFields(ctx, cfg, service)
			if err != nil {
				return err
			}
			if err := applyAuthMethod(r, rule.AuthMethod, fields["access_token"]); err != nil {
				return fmt.Errorf("service %q: %w", id, err)
			}
		}
		if err := i.applyServiceInjection(ctx, r, cfg, id, service, fields); err != nil {
			return fmt.Errorf("service %q: %w", id, err)
		}
	}
	return nil
}

func (i *Injector) serviceByID(ctx context.Context, cfg *config.Config, id string) (config.ServiceConfig, bool, error) {
	if service, ok := config.ServiceByID(cfg, id); ok {
		return service, true, nil
	}
	service, ok, err := serviceinfo.Get(ctx, i.secrets, id)
	if err != nil || !ok {
		if err != nil || config.HeaderValueFromEnv(cfg.Server.OAuth.MetadataURL) == "" {
			return config.ServiceConfig{}, ok, err
		}
		fetched, fetchErr := serviceinfo.Fetch(ctx, i.client, config.HeaderValueFromEnv(cfg.Server.OAuth.MetadataURL), config.HeaderValueFromEnv(cfg.Server.OAuth.MetadataToken), id)
		if fetchErr != nil {
			return config.ServiceConfig{}, false, fetchErr
		}
		if putErr := serviceinfo.Put(ctx, i.secrets, id, fetched); putErr != nil {
			return config.ServiceConfig{}, false, putErr
		}
		return fetched, true, nil
	}
	return service, true, nil
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
	case "slack-user-oauth-token":
		token, err := i.slackUserToken(ctx, cfg, cred)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+token)
	case "github-oauth-token":
		token, err := i.githubOAuthToken(ctx, cfg, cred)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+token)
	default:
		return fmt.Errorf("unsupported credential type %q", cred.Type)
	}
	return nil
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
			if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
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
		if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
			return "", "", err
		}
	}
	return token, version, nil
}

type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

type cachedFields struct {
	fields    map[string]string
	expiresAt time.Time
}

func (i *Injector) genericOAuthFields(ctx context.Context, cfg *config.Config, service config.ServiceConfig) (map[string]string, error) {
	oauthCfg := service.OAuth
	if oauthCfg == nil {
		return map[string]string{}, nil
	}
	credentialID := oauthCfg.CredentialID
	if value, ok := i.cache.Load("service:" + credentialID); ok {
		token := value.(cachedFields)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.fields, nil
		}
	}

	lockValue, _ := i.locks.LoadOrStore("service:"+credentialID, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	if value, ok := i.cache.Load("service:" + credentialID); ok {
		token := value.(cachedFields)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.fields, nil
		}
	}

	cred := config.CredentialConfig{ID: credentialID, Type: "generic-oauth", Params: map[string]string{}}
	fields := map[string]string{}
	for _, key := range []string{"access_token", "id_token", "token_type", "expires_in", "refresh_token"} {
		value, err := i.secretValue(ctx, cfg, cred, key)
		if err != nil {
			return nil, err
		}
		if value != "" {
			fields[key] = value
		}
	}
	if accessToken := fields["access_token"]; accessToken != "" && fields["refresh_token"] == "" {
		i.cache.Store("service:"+credentialID, cachedFields{fields: fields, expiresAt: time.Now().Add(10 * 365 * 24 * time.Hour)})
		return fields, nil
	}
	refreshToken := fields["refresh_token"]
	if refreshToken == "" {
		return nil, fmt.Errorf("service credential %q requires refresh_token or access_token", credentialID)
	}
	clientID, err := serviceClientValue(ctx, i.secrets, oauthCfg.ClientID, oauthCfg.ClientIDSecretRef)
	if err != nil {
		return nil, err
	}
	clientSecret, err := serviceClientValue(ctx, i.secrets, oauthCfg.ClientSecret, oauthCfg.ClientSecretRef)
	if err != nil {
		return nil, err
	}
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("service credential %q requires client_id and client_secret", credentialID)
	}
	refreshed, err := i.requestGenericOAuthToken(ctx, oauthCfg.TokenRequest.RefreshURL(oauthCfg.TokenURL), oauthCfg.TokenRequest, map[string]string{"refresh_token": refreshToken}, clientID, clientSecret, oauthCfg.TokenRequest.ResolvedRefreshGrantType())
	if err != nil {
		return nil, err
	}
	for key, value := range refreshed {
		fields[key] = value
		if key == "refresh_token" && value != "" {
			if err := i.putCredentialSecret(ctx, cfg, cred, key, value); err != nil {
				return nil, err
			}
		}
	}
	if fields["access_token"] == "" && fields["id_token"] == "" {
		return nil, fmt.Errorf("token endpoint response did not include access_token or id_token")
	}
	expiresAt := time.Now().Add(time.Hour)
	if expiresIn, ok := parseExpiresIn(fields["expires_in"]); ok {
		expiresAt = time.Now().Add(expiresIn)
	}
	i.cache.Store("service:"+credentialID, cachedFields{fields: fields, expiresAt: expiresAt})
	return fields, nil
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

	lockValue, _ := i.locks.LoadOrStore(cred.ID, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

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
			if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
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
		if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
			return "", err
		}
	}
	return token, nil
}

func (i *Injector) slackUserToken(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value, ok := i.cache.Load(cred.ID); ok {
		token := value.(cachedToken)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.accessToken, nil
		}
	}

	lockValue, _ := i.locks.LoadOrStore(cred.ID, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

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

	refreshToken, err := i.secretValue(ctx, cfg, cred, "refresh_token")
	if err != nil {
		return "", err
	}
	if refreshToken == "" {
		return "", fmt.Errorf("credential %q requires refresh_token or access_token", cred.ID)
	}

	tokenBrokerURL := config.HeaderValueFromEnv(cred.Params["token_broker_url"])
	if tokenBrokerURL != "" {
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
			if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
				return "", err
			}
		}
		return token, nil
	}

	slackCfg, hasSlackCfg := config.SlackOAuthConfigForCredential(cfg, cred.ID)
	tokenURL := cred.Params["refresh_token_url"]
	if tokenURL == "" && hasSlackCfg {
		tokenURL = slackCfg.RefreshTokenURL
	}
	if tokenURL == "" && hasSlackCfg {
		tokenURL = slackCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = "https://slack.com/api/oauth.v2.access"
	}
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	if clientID == "" && hasSlackCfg {
		var err error
		clientID, err = i.slackClientValue(ctx, slackCfg.ClientID, slackCfg.ClientIDSecretRef)
		if err != nil {
			return "", err
		}
	}
	clientSecret := config.HeaderValueFromEnv(cred.Params["client_secret"])
	if clientSecret == "" && hasSlackCfg {
		var err error
		clientSecret, err = i.slackClientValue(ctx, slackCfg.ClientSecret, slackCfg.ClientSecretRef)
		if err != nil {
			return "", err
		}
	}
	if clientID == "" || clientSecret == "" {
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
		if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
			return "", err
		}
	}
	return token, nil
}

func (i *Injector) githubOAuthToken(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value, ok := i.cache.Load(cred.ID); ok {
		token := value.(cachedToken)
		if time.Until(token.expiresAt) > 30*time.Second {
			return token.accessToken, nil
		}
	}

	lockValue, _ := i.locks.LoadOrStore(cred.ID, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

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

	refreshToken, err := i.secretValue(ctx, cfg, cred, "refresh_token")
	if err != nil {
		return "", err
	}
	if refreshToken == "" {
		return "", fmt.Errorf("credential %q requires refresh_token or access_token", cred.ID)
	}

	tokenBrokerURL := config.HeaderValueFromEnv(cred.Params["token_broker_url"])
	if tokenBrokerURL != "" {
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
			if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
				return "", err
			}
		}
		return token, nil
	}

	githubCfg, hasGitHubCfg := config.GitHubOAuthConfigForCredential(cfg, cred.ID)
	tokenURL := cred.Params["token_url"]
	if tokenURL == "" && hasGitHubCfg {
		tokenURL = githubCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = "https://github.com/login/oauth/access_token"
	}
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	if clientID == "" && hasGitHubCfg {
		var err error
		clientID, err = i.githubClientValue(ctx, githubCfg.ClientID, githubCfg.ClientIDSecretRef)
		if err != nil {
			return "", err
		}
	}
	clientSecret := config.HeaderValueFromEnv(cred.Params["client_secret"])
	if clientSecret == "" && hasGitHubCfg {
		var err error
		clientSecret, err = i.githubClientValue(ctx, githubCfg.ClientSecret, githubCfg.ClientSecretRef)
		if err != nil {
			return "", err
		}
	}
	if clientID == "" || clientSecret == "" {
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
		if err := i.putCredentialSecret(ctx, cfg, cred, "refresh_token", rotatedRefreshToken); err != nil {
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

func (i *Injector) slackClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, i.secrets, secretRef)
}

func (i *Injector) githubClientValue(ctx context.Context, literal, secretRef string) (string, error) {
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
	storageKey := credentialSecretKey(cfg, cred, userID, key)
	value, ok, err := i.secrets.Get(ctx, userID, storageKey)
	if err != nil {
		return "", err
	}
	if ok {
		return value, nil
	}
	if storageKey != key && key == "refresh_token" && strings.HasSuffix(cred.ID, ".google") {
		value, ok, err := i.secrets.Get(ctx, userID, key)
		if err != nil {
			return "", err
		}
		if ok {
			return value, nil
		}
	}
	return "", nil
}

func (i *Injector) rotatingSecretValue(ctx context.Context, cfg *config.Config, cred config.CredentialConfig, key string) (string, error) {
	userID := config.CredentialUserID(cfg, cred)
	storageKey := credentialSecretKey(cfg, cred, userID, key)
	value, ok, err := i.secrets.Get(ctx, userID, storageKey)
	if err != nil {
		return "", err
	}
	if ok {
		return value, nil
	}
	if storageKey != key && key == "refresh_token" && strings.HasSuffix(cred.ID, ".google") {
		value, ok, err := i.secrets.Get(ctx, userID, key)
		if err != nil {
			return "", err
		}
		if ok {
			return value, nil
		}
	}
	return config.HeaderValueFromEnv(cred.Params[key]), nil
}

func credentialSecretKey(cfg *config.Config, cred config.CredentialConfig, userID, key string) string {
	if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(userID) && cred.ID != "" {
		return cred.ID + "." + key
	}
	return key
}

func (i *Injector) putCredentialSecret(ctx context.Context, cfg *config.Config, cred config.CredentialConfig, key, value string) error {
	userID := config.CredentialUserID(cfg, cred)
	return i.secrets.Put(ctx, userID, credentialSecretKey(cfg, cred, userID, key), value)
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
	if !supportedTokenType(token.TokenType) {
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
	if !supportedTokenType(token.TokenType) {
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
	if !supportedTokenType(body.TokenType) {
		return "", fmt.Errorf("unsupported token_type %q", body.TokenType)
	}
	expiresIn := time.Duration(body.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}
	i.cache.Store(credentialID, cachedToken{accessToken: body.AccessToken, expiresAt: time.Now().Add(expiresIn)})
	return body.AccessToken, nil
}

func supportedTokenType(tokenType string) bool {
	return tokenType == "" || strings.EqualFold(tokenType, "bearer") || strings.EqualFold(tokenType, "user")
}

func serviceHostRule(service config.ServiceConfig, host, reqPath string) (config.ServiceHostRule, bool) {
	hostOnly := strings.ToLower(host)
	if splitHost, _, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = splitHost
	}
	for _, rule := range service.Hosts {
		if rule.Host != "" && strings.ToLower(rule.Host) != hostOnly {
			continue
		}
		if rule.HostSuffix != "" {
			suffix := strings.ToLower(rule.HostSuffix)
			if !strings.HasSuffix(hostOnly, suffix) || len(hostOnly) <= len(suffix) {
				continue
			}
		}
		if rule.PathPrefix != "" && !strings.HasPrefix(reqPath, rule.PathPrefix) {
			continue
		}
		return rule, true
	}
	return config.ServiceHostRule{}, false
}

func applyAuthMethod(r *http.Request, method, token string) error {
	switch method {
	case "", "none":
		return nil
	case "bearer":
		if token == "" {
			return errors.New("bearer auth requires access_token")
		}
		r.Header.Set("Authorization", "Bearer "+token)
	case "basic-x-access-token":
		if token == "" {
			return errors.New("basic-x-access-token auth requires access_token")
		}
		encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		r.Header.Set("Authorization", "Basic "+encoded)
	case "basic":
		if token == "" {
			return errors.New("basic auth requires access_token")
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(token))
		r.Header.Set("Authorization", "Basic "+encoded)
	default:
		return fmt.Errorf("unsupported authMethod %q", method)
	}
	return nil
}

func (i *Injector) applyServiceInjection(ctx context.Context, r *http.Request, cfg *config.Config, serviceID string, service config.ServiceConfig, fields map[string]string) error {
	credID := serviceID
	if service.OAuth != nil {
		credID = service.OAuth.CredentialID
	}
	for _, header := range service.Injection.Headers {
		value, err := i.renderInjection(ctx, cfg, credID, header.Value, fields)
		if err != nil {
			return err
		}
		r.Header.Set(header.Name, value)
	}
	if len(service.Injection.Query) > 0 {
		q := r.URL.Query()
		for _, param := range service.Injection.Query {
			value, err := i.renderInjection(ctx, cfg, credID, param.Value, fields)
			if err != nil {
				return err
			}
			q.Set(param.Name, value)
		}
		r.URL.RawQuery = q.Encode()
	}
	return nil
}

func (i *Injector) renderInjection(ctx context.Context, cfg *config.Config, credentialID, raw string, fields map[string]string) (string, error) {
	tmpl, err := template.New("injection").Funcs(template.FuncMap{
		"secret": func(key string) (string, error) {
			if credentialID == "" {
				return "", fmt.Errorf("secret %q requires oauth credential", key)
			}
			cred := config.CredentialConfig{ID: credentialID, Type: "generic-oauth", Params: map[string]string{}}
			return i.secretValue(ctx, cfg, cred, key)
		},
	}).Parse(raw)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, fields); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (i *Injector) requestGenericOAuthToken(ctx context.Context, tokenURL string, cfg config.TokenRequestConfig, extra map[string]string, clientID, clientSecret, grantType string) (map[string]string, error) {
	if tokenURL == "" {
		return nil, errors.New("tokenUrl is required")
	}
	body := map[string]string{}
	for key, value := range extra {
		if value != "" {
			body[key] = value
		}
	}
	if grantType != "" {
		body["grant_type"] = grantType
	}
	req, err := newTokenRequest(ctx, tokenURL, cfg, body, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	if cfg.SuccessField != "" {
		ok, _ := raw[cfg.SuccessField].(bool)
		if !ok {
			return nil, fmt.Errorf("token endpoint response %s was not true", cfg.SuccessField)
		}
	}
	fields := map[string]string{}
	for key, value := range raw {
		switch v := value.(type) {
		case string:
			fields[key] = v
		case float64:
			fields[key] = strconv.FormatInt(int64(v), 10)
		case bool:
			fields[key] = strconv.FormatBool(v)
		}
	}
	if tokenType := fields["token_type"]; !supportedTokenType(tokenType) {
		return nil, fmt.Errorf("unsupported token_type %q", tokenType)
	}
	return fields, nil
}

func newTokenRequest(ctx context.Context, tokenURL string, cfg config.TokenRequestConfig, body map[string]string, clientID, clientSecret string) (*http.Request, error) {
	if cfg.BodyFormat == "" {
		cfg.BodyFormat = "form"
	}
	if cfg.ClientAuth == "" {
		cfg.ClientAuth = "body"
	}
	if cfg.ClientAuth == "body" {
		body["client_id"] = clientID
		body["client_secret"] = clientSecret
	}
	var req *http.Request
	var err error
	switch cfg.BodyFormat {
	case "json":
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
		}
	default:
		form := url.Values{}
		for key, value := range body {
			form.Set(key, value)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return nil, err
	}
	if cfg.ClientAuth == "basic" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	return req, nil
}

func serviceClientValue(ctx context.Context, store secrets.Store, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, store, secretRef)
}

func parseExpiresIn(raw string) (time.Duration, bool) {
	if raw == "" {
		return 0, false
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}
