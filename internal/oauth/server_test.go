package oauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

type staticProvider struct {
	cfg *config.Config
}

func (p staticProvider) Load(context.Context) (*config.Config, error) {
	return p.cfg, nil
}

func (p staticProvider) Watch(ctx context.Context, out chan<- *config.Config) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestGoogleOAuthStartRedirectsToGoogle(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{RedirectURL: "http://localhost:8081/oauth/google/callback"},
		},
		Credentials: []config.CredentialConfig{
			{
				ID:   "google",
				Type: "google-oauth-refresh-token",
				Params: map[string]string{
					"client_id": "client-id",
					"scope":     "https://www.googleapis.com/auth/calendar",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, googleAuthURL+"?") {
		t.Fatalf("unexpected redirect: %s", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "client-id")
	assertQueryValue(t, query, "redirect_uri", "http://localhost:8081/oauth/google/callback")
	assertQueryValue(t, query, "scope", "https://www.googleapis.com/auth/calendar")
	assertQueryValue(t, query, "access_type", "offline")
	assertQueryValue(t, query, "prompt", "consent")
	if query.Get("state") == "" {
		t.Fatal("missing state")
	}
}

func TestGoogleOAuthStartUsesConfigGoogleClient(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				RedirectURL: "http://localhost:8081/oauth/google/callback",
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "config-client-id",
					ClientSecret: "config-client-secret",
					Scope:        "https://www.googleapis.com/auth/calendar",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "config-client-id")
	assertQueryValue(t, query, "redirect_uri", "http://localhost:8081/oauth/google/callback")
	assertQueryValue(t, query, "scope", "https://www.googleapis.com/auth/calendar")
}

func TestGoogleOAuthCallbackShowsRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "authorization_code")
		assertFormValue(t, r, "code", "auth-code")
		assertFormValue(t, r, "client_id", "client-id")
		assertFormValue(t, r, "client_secret", "client-secret")
		assertFormValue(t, r, "redirect_uri", "http://localhost:8081/oauth/google/callback")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"refresh_token": "refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{RedirectURL: "http://localhost:8081/oauth/google/callback"},
		},
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
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "google", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `refresh_token: "refresh-token"`) {
		t.Fatalf("refresh token not rendered: %s", rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "google", "refresh_token"); err != nil || !ok || got != "refresh-token" {
		t.Fatalf("refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestGoogleOAuthCallbackStoresConfigGoogleRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "authorization_code")
		assertFormValue(t, r, "code", "auth-code")
		assertFormValue(t, r, "client_id", "config-client-id")
		assertFormValue(t, r, "client_secret", "config-client-secret")
		assertFormValue(t, r, "redirect_uri", "http://localhost:8081/oauth/google/callback")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"refresh_token": "config-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				RedirectURL: "http://localhost:8081/oauth/google/callback",
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "config-client-id",
					ClientSecret: "config-client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "google-calendar", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "google-calendar", "refresh_token"); err != nil || !ok || got != "config-refresh-token" {
		t.Fatalf("refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func newOAuthTestStore(t *testing.T, cfg *config.Config) *config.Store {
	t.Helper()
	store, err := config.NewStore(context.Background(), staticProvider{cfg: cfg}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return store
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

func assertQueryValue(t *testing.T, values url.Values, key, want string) {
	t.Helper()
	if got := values.Get(key); got != want {
		t.Fatalf("unexpected query value for %s: got %q want %q", key, got, want)
	}
}

func assertFormValue(t *testing.T, r *http.Request, key, want string) {
	t.Helper()
	if got := r.Form.Get(key); got != want {
		t.Fatalf("unexpected form value for %s: got %q want %q", key, got, want)
	}
}
