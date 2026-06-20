package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestGoogleRefreshTokenUsesNamespacedGoogleClientSecretRefs(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "client_id", "service-client-id")
		assertFormValue(t, r, "client_secret", "service-client-secret")
		assertFormValue(t, r, "refresh_token", "stored-refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "service-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	for key, value := range map[string]string{
		"client-id":     "service-client-id",
		"client-secret": "service-client-secret",
		"refresh_token": "stored-refresh-token",
	} {
		if err := secretStore.Put(context.Background(), "service-a.google", key, value); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Google: config.GoogleOAuthConfig{
							ClientIDSecretRef: "service-a.google.client-id",
							ClientSecretRef:   "service-a.google.client-secret",
							TokenURL:          tokenEndpoint.URL,
						},
					},
				},
			},
		},
		Rules: []config.RuleConfig{
			{
				Name:        "service-a-google",
				Hosts:       []string{"www.googleapis.com"},
				Paths:       []string{"/calendar/v3/*"},
				Action:      "allow",
				Credentials: []string{"service-a.google"},
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

	if err := NewInjector(secretStore).Apply(context.Background(), req, cfg, []string{"service-a.google"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer service-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
}

func TestGoogleRefreshTokenUsesNamespacedGoogleClientEnvRefs(t *testing.T) {
	t.Setenv("SERVICE_A_GOOGLE_CLIENT_ID", "env-client-id")
	t.Setenv("SERVICE_A_GOOGLE_CLIENT_SECRET", "env-client-secret")

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "client_id", "env-client-id")
		assertFormValue(t, r, "client_secret", "env-client-secret")
		assertFormValue(t, r, "refresh_token", "stored-refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "env-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.google", "refresh_token", "stored-refresh-token"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Google: config.GoogleOAuthConfig{
							ClientIDSecretRef: "env:SERVICE_A_GOOGLE_CLIENT_ID",
							ClientSecretRef:   "env:SERVICE_A_GOOGLE_CLIENT_SECRET",
							TokenURL:          tokenEndpoint.URL,
						},
					},
				},
			},
		},
		Rules: []config.RuleConfig{
			{
				Name:        "service-a-google",
				Hosts:       []string{"www.googleapis.com"},
				Paths:       []string{"/calendar/v3/*"},
				Action:      "allow",
				Credentials: []string{"service-a.google"},
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

	if err := NewInjector(secretStore).Apply(context.Background(), req, cfg, []string{"service-a.google"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer env-access-token" {
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

func TestNotionRefreshTokenUsesNamespacedNotionClientSecretRefs(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "service-client-id" || password != "service-client-secret" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "service-access-token",
			"refresh_token": "service-rotated-refresh-token",
			"token_type":    "bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	secretStore := newMemorySecretStore()
	for key, value := range map[string]string{
		"client-id":     "service-client-id",
		"client-secret": "service-client-secret",
		"refresh_token": "stored-refresh-token",
	} {
		if err := secretStore.Put(context.Background(), "service-a.notion", key, value); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Notion: config.NotionOAuthConfig{
							ClientIDSecretRef: "service-a.notion.client-id",
							ClientSecretRef:   "service-a.notion.client-secret",
							TokenURL:          tokenEndpoint.URL,
						},
					},
				},
			},
		},
		Rules: []config.RuleConfig{
			{
				Name:        "service-a-notion",
				Hosts:       []string{"api.notion.com"},
				Paths:       []string{"/v1/*"},
				Action:      "allow",
				Credentials: []string{"service-a.notion"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.notion.com/v1/search", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := NewInjector(secretStore).Apply(context.Background(), req, cfg, []string{"service-a.notion"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer service-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
	if got, ok, err := secretStore.Get(context.Background(), "service-a.notion", "refresh_token"); err != nil || !ok || got != "service-rotated-refresh-token" {
		t.Fatalf("rotated refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func assertFormValue(t *testing.T, r *http.Request, key, want string) {
	t.Helper()
	if got := r.Form.Get(key); got != want {
		t.Fatalf("unexpected form value for %s: got %q want %q", key, got, want)
	}
}

type memorySecretStore struct {
	values map[string]string
}

func newMemorySecretStore() *memorySecretStore {
	return &memorySecretStore{values: map[string]string{}}
}

func (s *memorySecretStore) Get(_ context.Context, credentialID, key string) (string, bool, error) {
	value, ok := s.values[credentialID+":"+key]
	return value, ok, nil
}

func (s *memorySecretStore) Put(_ context.Context, credentialID, key, value string) error {
	s.values[credentialID+":"+key] = value
	return nil
}

func (s *memorySecretStore) Close() error {
	return nil
}
