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
)

type Injector struct {
	client *http.Client
	cache  sync.Map
}

func NewInjector() *Injector {
	return &Injector{client: &http.Client{Timeout: 10 * time.Second}}
}

func (i *Injector) Apply(ctx context.Context, r *http.Request, cfg *config.Config, ids []string) error {
	for _, id := range ids {
		cred, ok := config.CredentialByID(cfg, id)
		if !ok {
			return fmt.Errorf("credential %q not found", id)
		}
		if err := i.applyOne(ctx, r, cred); err != nil {
			return err
		}
	}
	return nil
}

func (i *Injector) applyOne(ctx context.Context, r *http.Request, cred config.CredentialConfig) error {
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
