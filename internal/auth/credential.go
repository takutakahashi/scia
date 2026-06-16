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
	default:
		return fmt.Errorf("unsupported credential type %q", cred.Type)
	}
	return nil
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
	if tokenURL == "" {
		tokenURL = cfg.Server.OAuth.Google.TokenURL
	}
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	if clientID == "" {
		clientID = config.HeaderValueFromEnv(cfg.Server.OAuth.Google.ClientID)
	}
	clientSecret := config.HeaderValueFromEnv(cred.Params["client_secret"])
	if clientSecret == "" {
		clientSecret = config.HeaderValueFromEnv(cfg.Server.OAuth.Google.ClientSecret)
	}
	refreshToken, err := i.secretValue(ctx, cred, "refresh_token")
	if err != nil {
		return "", err
	}
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return "", fmt.Errorf("credential %q requires client_id, client_secret, and refresh_token", cred.ID)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", refreshToken)
	return i.formToken(ctx, cred.ID, tokenURL, form)
}

func (i *Injector) secretValue(ctx context.Context, cred config.CredentialConfig, key string) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params[key]); value != "" {
		return value, nil
	}
	value, ok, err := i.secrets.Get(ctx, cred.ID, key)
	if err != nil {
		return "", err
	}
	if ok {
		return value, nil
	}
	return "", nil
}

func (i *Injector) formToken(ctx context.Context, credentialID, tokenURL string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	i.cache.Store(credentialID, cachedToken{accessToken: body.AccessToken, expiresAt: time.Now().Add(expiresIn)})
	return body.AccessToken, nil
}
