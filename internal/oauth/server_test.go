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

func TestFrontendIntegrationsReturnsConfiguredOAuthIntegrations(t *testing.T) {
	released := false
	calendarScopeEnabled := true
	driveScopeEnabled := false
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				RedirectURL: "http://localhost:8081/oauth/google/callback",
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"google-calendar": {
						Name:        "Google Calendar",
						IconURL:     "https://example.com/google-calendar.png",
						Description: "Connect Google Calendar.",
						Released:    &released,
						Setup: map[string]string{
							"project": "Google Cloud OAuth client",
						},
						Scopes: []config.OAuthIntegrationScopeConfig{
							{
								Value:     "https://www.googleapis.com/auth/calendar",
								ID:        "calendar-write",
								Name:      "Calendar write",
								Desc:      "Read and write calendars.",
								Group:     "calendar",
								GroupName: "Calendar access",
								GroupDesc: "Choose how much calendar access to grant.",
								Enabled:   &calendarScopeEnabled,
							},
							{
								Value:   "https://www.googleapis.com/auth/drive",
								ID:      "drive",
								Name:    "Drive",
								Enabled: &driveScopeEnabled,
							},
						},
					},
				},
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					Scope:        "https://www.googleapis.com/auth/calendar",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/integrations", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var body integrationsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Integrations) != 1 {
		t.Fatalf("unexpected integrations: %#v", body.Integrations)
	}
	got := body.Integrations[0]
	if got.ID != "google-calendar" || got.Provider != "google" || got.CredentialID != "google-calendar" {
		t.Fatalf("unexpected integration identity: %#v", got)
	}
	if got.Name != "Google Calendar" || got.IconURL != "https://example.com/google-calendar.png" || got.Description != "Connect Google Calendar." {
		t.Fatalf("metadata was not applied: %#v", got)
	}
	if got.Released {
		t.Fatalf("released flag was not applied: %#v", got)
	}
	if got.StartURL != "/oauth/google/start?credential=google-calendar" {
		t.Fatalf("unexpected start_url: %q", got.StartURL)
	}
	if got.Setup["callback_url"] != "http://localhost:8081/oauth/google/callback" {
		t.Fatalf("unexpected callback_url: %#v", got.Setup)
	}
	if got.Setup["auth_url"] != googleAuthURL || got.Setup["token_url"] != googleTokenURL || got.Setup["revoke_url"] != googleRevokeURL {
		t.Fatalf("unexpected setup URLs: %#v", got.Setup)
	}
	if got.Setup["project"] != "Google Cloud OAuth client" {
		t.Fatalf("custom setup metadata missing: %#v", got.Setup)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("unexpected scopes: %#v", got.Scopes)
	}
	if got.Scopes[0].ID != "calendar-write" || got.Scopes[0].Name != "Calendar write" || got.Scopes[0].Desc != "Read and write calendars." || got.Scopes[0].Group != "calendar" || got.Scopes[0].GroupName != "Calendar access" || got.Scopes[0].GroupDesc != "Choose how much calendar access to grant." || !got.Scopes[0].Enabled {
		t.Fatalf("unexpected first scope: %#v", got.Scopes[0])
	}
	if got.Scopes[1].ID != "drive" || got.Scopes[1].Name != "Drive" || got.Scopes[1].Enabled {
		t.Fatalf("unexpected second scope: %#v", got.Scopes[1])
	}
}

func TestFrontendIntegrationsReturnsNamespacedOAuthIntegrations(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Todoist: config.TodoistOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
							Scope:        "data:read,data:read_write",
							RedirectURL:  "https://service-a.example.com/oauth/todoist/callback",
						},
					},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/integrations", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var body integrationsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Integrations) != 1 {
		t.Fatalf("unexpected integrations: %#v", body.Integrations)
	}
	got := body.Integrations[0]
	if got.ID != "service-a.todoist" || got.Namespace != "service-a" || got.Provider != "todoist" {
		t.Fatalf("unexpected namespaced integration: %#v", got)
	}
	if got.StartURL != "/oauth/service-a/todoist/start" {
		t.Fatalf("unexpected start_url: %q", got.StartURL)
	}
	if got.AuthorizationURLEndpoint != "/oauth/service-a/todoist/authorization-url" {
		t.Fatalf("unexpected authorization_url_endpoint: %q", got.AuthorizationURLEndpoint)
	}
	if got.Setup["callback_url"] != "https://service-a.example.com/oauth/todoist/callback" {
		t.Fatalf("unexpected setup: %#v", got.Setup)
	}
	if len(got.Scopes) != 2 || got.Scopes[0].ID != "scope-1" || got.Scopes[0].Name != "Scope 1" || got.Scopes[1].ID != "scope-2" || got.Scopes[1].Name != "Scope 2" {
		t.Fatalf("unexpected scopes: %#v", got.Scopes)
	}
}

func TestNamespaceTodoistAuthorizationURLUsesEnabledMetadataScopesByDefault(t *testing.T) {
	readScopeEnabled := true
	writeScopeEnabled := false
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"service-a.todoist": {
						Scopes: []config.OAuthIntegrationScopeConfig{
							{Value: "data:read", Enabled: &readScopeEnabled},
							{Value: "data:read_write", Enabled: &writeScopeEnabled},
						},
					},
				},
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Todoist: config.TodoistOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
							Scope:        "data:read,data:read_write",
							RedirectURL:  "https://service-a.example.com/oauth/todoist/callback",
						},
					},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/service-a/todoist/authorization-url?state=state-1", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["scope"] != "data:read" {
		t.Fatalf("unexpected scope: %#v", body)
	}
	location, err := url.Parse(body["authorization_url"])
	if err != nil {
		t.Fatal(err)
	}
	assertQueryValue(t, location.Query(), "scope", "data:read")
}

func TestNamespaceTodoistAuthorizationURLRejectsUnknownMetadataScopeSelection(t *testing.T) {
	readScopeEnabled := true
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"service-a.todoist": {
						Scopes: []config.OAuthIntegrationScopeConfig{
							{Value: "data:read", Enabled: &readScopeEnabled},
						},
					},
				},
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Todoist: config.TodoistOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
						},
					},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/service-a/todoist/authorization-url?scope=data:delete", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "is not allowed") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestFrontendIntegrationsRequiresGet(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/api/integrations", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
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

func TestGoogleOAuthStartUsesEnabledMetadataScopesByDefault(t *testing.T) {
	readScopeEnabled := true
	writeScopeEnabled := false
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				RedirectURL: "http://localhost:8081/oauth/google/callback",
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"google-calendar": {
						Scopes: []config.OAuthIntegrationScopeConfig{
							{ID: "calendar-read", Value: "https://www.googleapis.com/auth/calendar.readonly", Enabled: &readScopeEnabled},
							{ID: "calendar-write", Value: "https://www.googleapis.com/auth/calendar", Enabled: &writeScopeEnabled},
						},
					},
				},
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "config-client-id",
					ClientSecret: "config-client-secret",
					Scope:        "https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	assertQueryValue(t, parsed.Query(), "scope", "https://www.googleapis.com/auth/calendar.readonly")
}

func TestGoogleOAuthStartAcceptsAllowedMetadataScopeSelection(t *testing.T) {
	readScopeEnabled := true
	writeScopeEnabled := false
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				RedirectURL: "http://localhost:8081/oauth/google/callback",
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"google-calendar": {
						Scopes: []config.OAuthIntegrationScopeConfig{
							{ID: "calendar-read", Value: "https://www.googleapis.com/auth/calendar.readonly", Enabled: &readScopeEnabled},
							{ID: "calendar-write", Value: "https://www.googleapis.com/auth/calendar", Enabled: &writeScopeEnabled},
						},
					},
				},
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "config-client-id",
					ClientSecret: "config-client-secret",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar&scope=calendar-read%20calendar-write", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	assertQueryValue(t, parsed.Query(), "scope", "https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar")
}

func TestGoogleOAuthStartRejectsMultipleMetadataScopesInSameGroup(t *testing.T) {
	readScopeEnabled := true
	writeScopeEnabled := false
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				RedirectURL: "http://localhost:8081/oauth/google/callback",
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"google-calendar": {
						Scopes: []config.OAuthIntegrationScopeConfig{
							{ID: "calendar-read", Value: "https://www.googleapis.com/auth/calendar.readonly", Group: "calendar", Enabled: &readScopeEnabled},
							{ID: "calendar-write", Value: "https://www.googleapis.com/auth/calendar", Group: "calendar", Enabled: &writeScopeEnabled},
						},
					},
				},
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "config-client-id",
					ClientSecret: "config-client-secret",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar&scope=calendar-read%20calendar-write", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "can include only one selected scope") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestGoogleOAuthStartRejectsUnknownMetadataScopeSelection(t *testing.T) {
	readScopeEnabled := true
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"google-calendar": {
						Scopes: []config.OAuthIntegrationScopeConfig{
							{Value: "https://www.googleapis.com/auth/calendar.readonly", Enabled: &readScopeEnabled},
						},
					},
				},
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "config-client-id",
					ClientSecret: "config-client-secret",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "is not allowed") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
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

func TestTodoistOAuthStartRedirectsToTodoist(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Todoist: config.TodoistOAuthConfig{
					CredentialID: "todoist",
					ClientID:     "todoist-client-id",
					ClientSecret: "todoist-client-secret",
					Scope:        "data:read_write",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/todoist/start?credential=todoist", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, todoistAuthURL+"?") {
		t.Fatalf("unexpected redirect: %s", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "todoist-client-id")
	assertQueryValue(t, query, "scope", "data:read_write")
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

func TestTodoistOAuthCallbackStoresRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "code", "auth-code")
		assertFormValue(t, r, "client_id", "todoist-client-id")
		assertFormValue(t, r, "client_secret", "todoist-client-secret")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "todoist-access-token",
			"refresh_token": "todoist-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Todoist: config.TodoistOAuthConfig{
					CredentialID: "todoist",
					ClientID:     "todoist-client-id",
					ClientSecret: "todoist-client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "todoist", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/todoist/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "todoist", "refresh_token"); err != nil || !ok || got != "todoist-refresh-token" {
		t.Fatalf("refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestTodoistOAuthCallbackStoresLegacyAccessToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "legacy-access-token",
			"token_type":   "Bearer",
			"expires_in":   315360000,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Todoist: config.TodoistOAuthConfig{
					CredentialID: "todoist",
					ClientID:     "todoist-client-id",
					ClientSecret: "todoist-client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "todoist", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/todoist/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "todoist", "access_token"); err != nil || !ok || got != "legacy-access-token" {
		t.Fatalf("access token not stored: got=%q ok=%v err=%v", got, ok, err)
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

func TestNamespaceTodoistAuthorizationURLUsesSecretRefClientID(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Todoist: config.TodoistOAuthConfig{
							ClientIDSecretRef: "service-a.todoist.client-id",
							ClientSecretRef:   "service-a.todoist.client-secret",
							Scope:             "data:read_write",
						},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.todoist", "client-id", "secret-client-id"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/service-a/todoist/authorization-url?state=state-1", nil)
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
	assertQueryValue(t, query, "scope", "data:read_write")
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

func TestNamespaceTodoistAccessTokenUsesStoredRefreshTokenAndStoresRotatedRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "refresh_token", "stored-refresh-token")
		assertFormValue(t, r, "client_id", "secret-client-id")
		assertFormValue(t, r, "client_secret", "secret-client-secret")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "stored-access-token",
			"refresh_token": "rotated-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Todoist: config.TodoistOAuthConfig{
							ClientIDSecretRef: "service-a.todoist.client-id",
							ClientSecretRef:   "service-a.todoist.client-secret",
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
		if err := secretStore.Put(context.Background(), "service-a.todoist", key, value); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/todoist/access-token", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stored-access-token") {
		t.Fatalf("token response was not proxied: %s", rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "service-a.todoist", "refresh_token"); err != nil || !ok || got != "rotated-refresh-token" {
		t.Fatalf("rotated refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestNamespaceTodoistAccessTokenUsesStoredAccessToken(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Namespaces: map[string]config.OAuthNamespaceConfig{
					"service-a": {
						Todoist: config.TodoistOAuthConfig{
							ClientID:     "client-id",
							ClientSecret: "client-secret",
						},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "service-a.todoist", "access_token", "legacy-access-token"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/service-a/todoist/access-token", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "legacy-access-token") {
		t.Fatalf("token response did not include stored access token: %s", rec.Body.String())
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
