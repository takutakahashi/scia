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

func TestHealthz(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/_scia/healthz", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
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

func TestNotionOAuthStartRedirectsToNotion(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Notion: config.NotionOAuthConfig{
					CredentialID: "notion-workspace",
					ClientID:     "notion-client-id",
					ClientSecret: "notion-client-secret",
					RedirectURL:  "http://localhost:8081/oauth/notion/callback",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/notion/start?credential=notion-workspace", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, notionAuthURL+"?") {
		t.Fatalf("unexpected redirect: %s", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "notion-client-id")
	assertQueryValue(t, query, "redirect_uri", "http://localhost:8081/oauth/notion/callback")
	assertQueryValue(t, query, "response_type", "code")
	assertQueryValue(t, query, "owner", "user")
	if query.Get("state") == "" {
		t.Fatal("missing state")
	}
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

func TestNotionOAuthCallbackUsesJSONBasicAuthAndStoresRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type: %q", got)
		}
		if got := r.Header.Get("Notion-Version"); got != notionVersion {
			t.Fatalf("unexpected Notion-Version: %q", got)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "notion-client-id" || password != "notion-client-secret" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["grant_type"] != "authorization_code" || body["code"] != "auth-code" || body["redirect_uri"] != "http://localhost:8081/oauth/notion/callback" {
			t.Fatalf("unexpected token request body: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "notion-access-token",
			"refresh_token": "notion-refresh-token",
			"token_type":    "bearer",
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Notion: config.NotionOAuthConfig{
					CredentialID:  "notion-workspace",
					ClientID:      "notion-client-id",
					ClientSecret:  "notion-client-secret",
					TokenURL:      tokenEndpoint.URL,
					RedirectURL:   "http://localhost:8081/oauth/notion/callback",
					NotionVersion: notionVersion,
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "notion-workspace", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/notion/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "notion-workspace", "refresh_token"); err != nil || !ok || got != "notion-refresh-token" {
		t.Fatalf("refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestNamespaceGoogleAuthorizationURLUsesSecretRefClientID(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Google: config.GoogleOAuthConfig{
							ClientIDSecretRef: "service-a.google.client-id",
							ClientSecretRef:   "service-a.google.client-secret",
							Scope:             "https://www.googleapis.com/auth/calendar",
							RedirectURL:       "https://service-a.example.com/oauth/callback",
						},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.google", "client-id", "secret-client-id"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/service-a/google/authorization-url?state=state-1", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body["authorization_url"])
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "secret-client-id")
	assertQueryValue(t, query, "redirect_uri", "https://service-a.example.com/oauth/callback")
	assertQueryValue(t, query, "scope", "https://www.googleapis.com/auth/calendar")
	assertQueryValue(t, query, "state", "state-1")
	if strings.Contains(body["authorization_url"], "client-secret") {
		t.Fatalf("authorization URL leaked client secret: %s", body["authorization_url"])
	}
}

func TestNamespaceNotionAuthorizationURLUsesSecretRefClientID(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Notion: config.NotionOAuthConfig{
							ClientIDSecretRef: "service-a.notion.client-id",
							ClientSecretRef:   "service-a.notion.client-secret",
							RedirectURL:       "https://service-a.example.com/oauth/notion/callback",
						},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.notion", "client-id", "secret-client-id"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/service-a/notion/authorization-url?state=state-1", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body["authorization_url"])
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "secret-client-id")
	assertQueryValue(t, query, "redirect_uri", "https://service-a.example.com/oauth/notion/callback")
	assertQueryValue(t, query, "owner", "user")
	assertQueryValue(t, query, "state", "state-1")
	if strings.Contains(body["authorization_url"], "client-secret") {
		t.Fatalf("authorization URL leaked client secret: %s", body["authorization_url"])
	}
}

func TestNamespaceGoogleTokenInjectsClientSecret(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "refresh_token", "refresh-token")
		assertFormValue(t, r, "client_id", "secret-client-id")
		assertFormValue(t, r, "client_secret", "secret-client-secret")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
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
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.google", "client-id", "secret-client-id"); err != nil {
		t.Fatal(err)
	}
	if err := secretStore.Put(context.Background(), "service-a.google", "client-secret", "secret-client-secret"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/google/token", strings.NewReader("refresh_token=refresh-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "access-token") {
		t.Fatalf("token response was not proxied: %s", rec.Body.String())
	}
}

func TestNamespaceGoogleAccessTokenUsesStoredRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "refresh_token", "stored-refresh-token")
		assertFormValue(t, r, "client_id", "secret-client-id")
		assertFormValue(t, r, "client_secret", "secret-client-secret")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stored-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
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
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.google", "client-id", "secret-client-id"); err != nil {
		t.Fatal(err)
	}
	if err := secretStore.Put(context.Background(), "service-a.google", "client-secret", "secret-client-secret"); err != nil {
		t.Fatal(err)
	}
	if err := secretStore.Put(context.Background(), "service-a.google", "refresh_token", "stored-refresh-token"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/google/access-token", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stored-access-token") {
		t.Fatalf("token response was not proxied: %s", rec.Body.String())
	}
}

func TestNamespaceNotionAccessTokenUsesStoredRefreshTokenAndStoresRotatedRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Notion-Version"); got != notionVersion {
			t.Fatalf("unexpected Notion-Version: %q", got)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "secret-client-id" || password != "secret-client-secret" {
			t.Fatalf("unexpected basic auth: username=%q password=%q ok=%v", username, password, ok)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["grant_type"] != "refresh_token" || body["refresh_token"] != "stored-refresh-token" {
			t.Fatalf("unexpected token request body: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "stored-access-token",
			"refresh_token": "rotated-refresh-token",
			"token_type":    "bearer",
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
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
	})
	secretStore := newMemorySecretStore()
	for key, value := range map[string]string{
		"client-id":     "secret-client-id",
		"client-secret": "secret-client-secret",
		"refresh_token": "stored-refresh-token",
	} {
		if err := secretStore.Put(context.Background(), "service-a.notion", key, value); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/notion/access-token", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stored-access-token") {
		t.Fatalf("token response was not proxied: %s", rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "service-a.notion", "refresh_token"); err != nil || !ok || got != "rotated-refresh-token" {
		t.Fatalf("rotated refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestNamespaceGoogleAccessTokenRequiresBrokerToken(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				BrokerToken: "broker-shared-token",
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Google: config.GoogleOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
						},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.google", "refresh_token", "stored-refresh-token"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/google/access-token", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "scia-oauth-broker") {
		t.Fatalf("unexpected WWW-Authenticate header: %q", got)
	}
}

func TestNamespaceGoogleAccessTokenAcceptsBrokerToken(t *testing.T) {
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

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				BrokerToken: "broker-shared-token",
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Google: config.GoogleOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
							TokenURL:     tokenEndpoint.URL,
						},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.google", "refresh_token", "stored-refresh-token"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/google/access-token", nil)
	req.Header.Set("Authorization", "Bearer broker-shared-token")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stored-access-token") {
		t.Fatalf("token response was not proxied: %s", rec.Body.String())
	}
}

func TestNamespaceGoogleAccessTokenUsesKubernetesUserSecret(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "refresh_token", "user-refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "user-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{Mode: "kubernetes"},
			Users: map[string]config.UserConfig{
				"alice": {SecretName: "scia-oauth-alice"},
			},
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"alice": {
						Google: config.GoogleOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
							TokenURL:     tokenEndpoint.URL,
						},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "alice", "refresh_token", "user-refresh-token"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/alice/google/access-token", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "user-access-token") {
		t.Fatalf("token response was not proxied: %s", rec.Body.String())
	}
}

func TestNamespaceGoogleAccessTokenRequiresStoredRefreshToken(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Google: config.GoogleOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
						},
					},
				},
			},
		},
	})
	srv := NewServer(store, newMemorySecretStore(), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/google/access-token", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGoogleOAuthCallbackStoresRefreshTokenForKubernetesUser(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"refresh_token": "k8s-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{Mode: "kubernetes"},
			Users: map[string]config.UserConfig{
				"alice": {SecretName: "scia-oauth-alice"},
			},
			OAuth: config.OAuthConfig{
				RedirectURL: "http://localhost:8081/oauth/google/callback",
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{User: "alice", CredentialID: "google-calendar", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "alice", "refresh_token"); err != nil || !ok || got != "k8s-refresh-token" {
		t.Fatalf("refresh token not stored for user: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestGoogleOAuthStartRequiresUserInKubernetesMode(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{Mode: "kubernetes"},
			Users: map[string]config.UserConfig{
				"alice": {SecretName: "scia-oauth-alice"},
			},
			OAuth: config.OAuthConfig{
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", rec.Code)
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
