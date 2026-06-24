package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

func TestGoogleRefreshTokenInjectsAccessToken(t *testing.T) {
	var tokenRequests int
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "client_id", "client-id")
		assertFormValue(t, r, "client_secret", "client-secret")
		assertFormValue(t, r, "refresh_token", "refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "google-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{
				ID:   "google",
				Type: "google-oauth-refresh-token",
				Params: map[string]string{
					"token_url":     tokenEndpoint.URL,
					"client_id":     "client-id",
					"client_secret": "client-secret",
					"refresh_token": "refresh-token",
				},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/calendar/v3/users/me/calendarList", nil)
	if err != nil {
		t.Fatal(err)
	}

	injector := NewInjector(secrets.NoopStore{})
	if err := injector.Apply(context.Background(), req, cfg, []string{"google"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer google-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}

	secondReq, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/calendar/v3/users/me/calendarList", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := injector.Apply(context.Background(), secondReq, cfg, []string{"google"}); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("expected token response to be cached, got %d token requests", tokenRequests)
	}
}

func TestGoogleRefreshTokenUsesSecretStore(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "refresh_token", "stored-refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stored-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "google", "refresh_token", "stored-refresh-token"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{
				ID:   "google",
				Type: "google-oauth-refresh-token",
				Params: map[string]string{
					"token_url":     tokenEndpoint.URL,
					"client_id":     "client-id",
					"client_secret": "client-secret",
				},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/calendar/v3/users/me/calendarList", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := NewInjector(secretStore).Apply(context.Background(), req, cfg, []string{"google"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer stored-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
}

func TestGoogleRefreshTokenUsesTokenBroker(t *testing.T) {
	var tokenRequests int
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer broker-shared-token" {
			t.Fatalf("unexpected broker authorization header: %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "refresh_token", "broker-refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "broker-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{
				ID:   "google",
				Type: "google-oauth-refresh-token",
				Params: map[string]string{
					"refresh_token":      "broker-refresh-token",
					"token_broker_url":   tokenEndpoint.URL,
					"token_broker_token": "broker-shared-token",
				},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/calendar/v3/users/me/calendarList", nil)
	if err != nil {
		t.Fatal(err)
	}

	injector := NewInjector(secrets.NoopStore{})
	if err := injector.Apply(context.Background(), req, cfg, []string{"google"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer broker-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}

	secondReq, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/calendar/v3/users/me/calendarList", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := injector.Apply(context.Background(), secondReq, cfg, []string{"google"}); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("expected broker response to be cached, got %d token requests", tokenRequests)
	}
}

func TestGoogleRefreshTokenUsesConfigGoogleClient(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "client_id", "config-client-id")
		assertFormValue(t, r, "client_secret", "config-client-secret")
		assertFormValue(t, r, "refresh_token", "stored-refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "config-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "google-calendar", "refresh_token", "stored-refresh-token"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "config-client-id",
					ClientSecret: "config-client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
		Rules: []config.RuleConfig{
			{
				Name:        "google-calendar",
				Hosts:       []string{"www.googleapis.com"},
				Paths:       []string{"/calendar/v3/*"},
				Action:      "allow",
				Credentials: []string{"google-calendar"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/calendar/v3/users/me/calendarList", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := NewInjector(secretStore).Apply(context.Background(), req, cfg, []string{"google-calendar"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer config-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
}

func TestNotionRefreshTokenInjectsAccessTokenAndStoresRotatedRefreshToken(t *testing.T) {
	var tokenRequests int
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type: %q", got)
		}
		if got := r.Header.Get("Notion-Version"); got != "2026-03-11" {
			t.Fatalf("unexpected Notion-Version: %q", got)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "client-id" || password != "client-secret" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["grant_type"] != "refresh_token" || body["refresh_token"] != "refresh-token" {
			t.Fatalf("unexpected token request body: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "notion-access-token",
			"refresh_token": "rotated-refresh-token",
			"token_type":    "bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{
				ID:   "notion",
				Type: "notion-oauth-refresh-token",
				Params: map[string]string{
					"token_url":     tokenEndpoint.URL,
					"client_id":     "client-id",
					"client_secret": "client-secret",
					"refresh_token": "refresh-token",
				},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.notion.com/v1/search", nil)
	if err != nil {
		t.Fatal(err)
	}

	injector := NewInjector(secretStore)
	if err := injector.Apply(context.Background(), req, cfg, []string{"notion"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer notion-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
	if got := req.Header.Get("Notion-Version"); got != "2026-03-11" {
		t.Fatalf("unexpected Notion-Version: %q", got)
	}
	if got, ok, err := secretStore.Get(context.Background(), "notion", "refresh_token"); err != nil || !ok || got != "rotated-refresh-token" {
		t.Fatalf("rotated refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}

	secondReq, err := http.NewRequest(http.MethodGet, "https://api.notion.com/v1/search", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := injector.Apply(context.Background(), secondReq, cfg, []string{"notion"}); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("expected token response to be cached, got %d token requests", tokenRequests)
	}
}

func TestTodoistRefreshTokenInjectsAccessTokenAndStoresRotatedRefreshToken(t *testing.T) {
	var tokenRequests int
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "client_id", "client-id")
		assertFormValue(t, r, "client_secret", "client-secret")
		assertFormValue(t, r, "refresh_token", "refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "todoist-access-token",
			"refresh_token": "rotated-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{
				ID:   "todoist",
				Type: "todoist-oauth-refresh-token",
				Params: map[string]string{
					"token_url":     tokenEndpoint.URL,
					"client_id":     "client-id",
					"client_secret": "client-secret",
					"refresh_token": "refresh-token",
				},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.todoist.com/api/v1/tasks", nil)
	if err != nil {
		t.Fatal(err)
	}

	injector := NewInjector(secretStore)
	if err := injector.Apply(context.Background(), req, cfg, []string{"todoist"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer todoist-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
	if got, ok, err := secretStore.Get(context.Background(), "todoist", "refresh_token"); err != nil || !ok || got != "rotated-refresh-token" {
		t.Fatalf("rotated refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}

	secondReq, err := http.NewRequest(http.MethodGet, "https://api.todoist.com/api/v1/tasks", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := injector.Apply(context.Background(), secondReq, cfg, []string{"todoist"}); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("expected token response to be cached, got %d token requests", tokenRequests)
	}
}

func TestTodoistRefreshTokenUsesStoredAccessToken(t *testing.T) {
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "todoist", "access_token", "legacy-access-token"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{ID: "todoist", Type: "todoist-oauth-refresh-token", Params: map[string]string{}},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.todoist.com/api/v1/tasks", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := NewInjector(secretStore).Apply(context.Background(), req, cfg, []string{"todoist"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer legacy-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
}

func TestGitHubOAuthTokenUsesStoredAccessToken(t *testing.T) {
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "github", "access_token", "github-access-token"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{ID: "github", Type: "github-oauth-token", Params: map[string]string{}},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := NewInjector(secretStore).Apply(context.Background(), req, cfg, []string{"github"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer github-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
}

func TestSlackUserTokenInjectsAccessTokenAndStoresRotatedRefreshToken(t *testing.T) {
	var tokenRequests int
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "client_id", "client-id")
		assertFormValue(t, r, "client_secret", "client-secret")
		assertFormValue(t, r, "refresh_token", "refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":            true,
			"access_token":  "slack-access-token",
			"refresh_token": "rotated-refresh-token",
			"token_type":    "user",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{
				ID:   "slack",
				Type: "slack-user-oauth-token",
				Params: map[string]string{
					"refresh_token_url": tokenEndpoint.URL,
					"client_id":         "client-id",
					"client_secret":     "client-secret",
					"refresh_token":     "refresh-token",
				},
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://slack.com/api/users.info", nil)
	if err != nil {
		t.Fatal(err)
	}

	injector := NewInjector(secretStore)
	if err := injector.Apply(context.Background(), req, cfg, []string{"slack"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer slack-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
	if got, ok, err := secretStore.Get(context.Background(), "slack", "refresh_token"); err != nil || !ok || got != "rotated-refresh-token" {
		t.Fatalf("rotated refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}

	secondReq, err := http.NewRequest(http.MethodGet, "https://slack.com/api/users.info", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := injector.Apply(context.Background(), secondReq, cfg, []string{"slack"}); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 {
		t.Fatalf("expected token response to be cached, got %d tokenRequests", tokenRequests)
	}
}

func TestTodoistRefreshTokenSerializesConcurrentRefreshes(t *testing.T) {
	var mu sync.Mutex
	var tokenRequests int
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokenRequests++
		mu.Unlock()
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "refresh_token", "refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "todoist-access-token",
			"refresh_token": "rotated-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "todoist", "refresh_token", "refresh-token"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Credentials: []config.CredentialConfig{
			{
				ID:   "todoist",
				Type: "todoist-oauth-refresh-token",
				Params: map[string]string{
					"token_url":     tokenEndpoint.URL,
					"client_id":     "client-id",
					"client_secret": "client-secret",
				},
			},
		},
	}
	injector := NewInjector(secretStore)

	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, "https://api.todoist.com/api/v1/tasks", nil)
			if err != nil {
				errs <- err
				return
			}
			if err := injector.Apply(context.Background(), req, cfg, []string{"todoist"}); err != nil {
				errs <- err
				return
			}
			if got := req.Header.Get("Authorization"); got != "Bearer todoist-access-token" {
				errs <- fmt.Errorf("unexpected authorization header: %q", got)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	mu.Lock()
	gotRequests := tokenRequests
	mu.Unlock()
	if gotRequests != 1 {
		t.Fatalf("expected one token request, got %d", gotRequests)
	}
}

func assertFormValue(t *testing.T, r *http.Request, key, want string) {
	t.Helper()
	if got := r.Form.Get(key); got != want {
		t.Fatalf("unexpected form value for %s: got %q want %q", key, got, want)
	}
}

type memorySecretStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newMemorySecretStore() *memorySecretStore {
	return &memorySecretStore{values: map[string]string{}}
}

func (s *memorySecretStore) Get(_ context.Context, credentialID, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[credentialID+":"+key]
	return value, ok, nil
}

func (s *memorySecretStore) Put(_ context.Context, credentialID, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[credentialID+":"+key] = value
	return nil
}

func (s *memorySecretStore) Delete(_ context.Context, credentialID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, credentialID+":"+key)
	return nil
}

func (s *memorySecretStore) Close() error {
	return nil
}
