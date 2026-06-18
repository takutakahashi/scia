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
