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
	"github.com/takutakahashi/scia/internal/serviceinfo"
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
	if _, ok := got.Setup["auth_url"]; ok {
		t.Fatalf("upstream auth URL leaked in setup: %#v", got.Setup)
	}
	if _, ok := got.Setup["token_url"]; ok {
		t.Fatalf("upstream token URL leaked in setup: %#v", got.Setup)
	}
	if _, ok := got.Setup["revoke_url"]; ok {
		t.Fatalf("upstream revoke URL leaked in setup: %#v", got.Setup)
	}
	if _, ok := got.Setup["project"]; ok {
		t.Fatalf("non-broker setup metadata leaked in setup: %#v", got.Setup)
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

func TestServiceMetadataReturnsConfiguredService(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			AdminToken: "admin-token",
			Services: config.ServicesConfig{
				"mock-dex-api": {
					Hosts: []config.ServiceHostRule{{Host: "mock-api.local"}},
					OAuth: &config.ServiceOAuthConfig{
						ClientID:     "client-id",
						ClientSecret: "client-secret",
						AuthURL:      "http://dex.example/dex/auth",
						TokenURL:     "http://dex.example/dex/token",
					},
					Injection: config.ServiceInjectionConfig{Headers: []config.InjectionTemplate{
						{Name: "X-ID-Token", Value: "{{ .id_token }}"},
					}},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/services/mock-dex-api", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		ID      string               `json:"id"`
		Service config.ServiceConfig `json:"service"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ID != "mock-dex-api" {
		t.Fatalf("unexpected id: %q", body.ID)
	}
	if body.Service.OAuth == nil || body.Service.OAuth.CredentialID != "mock-dex-api" {
		t.Fatalf("credential id was not defaulted: %#v", body.Service.OAuth)
	}
	if body.Service.OAuth.ClientID != "" || body.Service.OAuth.ClientSecret != "" {
		t.Fatalf("oauth client values leaked in metadata response: %#v", body.Service.OAuth)
	}
	if len(body.Service.Hosts) != 1 || body.Service.Hosts[0].AuthMethod != "bearer" {
		t.Fatalf("host defaults were not applied: %#v", body.Service.Hosts)
	}
	if len(body.Service.Injection.Headers) != 1 || body.Service.Injection.Headers[0].Name != "X-ID-Token" {
		t.Fatalf("unexpected injection metadata: %#v", body.Service.Injection)
	}
}

func TestServiceMetadataListReturnsConfiguredServices(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			AdminToken: "admin-token",
			Services: config.ServicesConfig{
				"mock-dex-api": {
					Hosts: []config.ServiceHostRule{{Host: "mock-api.local"}},
					OAuth: &config.ServiceOAuthConfig{
						ClientID:     "client-id",
						ClientSecret: "client-secret",
						AuthURL:      "http://dex.example/dex/auth",
						TokenURL:     "http://dex.example/dex/token",
					},
				},
				"other-api": {
					Hosts: []config.ServiceHostRule{{Host: "other.local", AuthMethod: "none"}},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/services", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var body serviceinfo.ListResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Services) != 2 {
		t.Fatalf("unexpected services: %#v", body.Services)
	}
	if body.Services[0].ID != "mock-dex-api" || body.Services[1].ID != "other-api" {
		t.Fatalf("services were not sorted by id: %#v", body.Services)
	}
	if body.Services[0].Service.OAuth == nil || body.Services[0].Service.OAuth.CredentialID != "mock-dex-api" {
		t.Fatalf("credential id was not defaulted: %#v", body.Services[0].Service.OAuth)
	}
	if body.Services[0].Service.OAuth.ClientID != "" || body.Services[0].Service.OAuth.ClientSecret != "" {
		t.Fatalf("oauth client values leaked in metadata list response: %#v", body.Services[0].Service.OAuth)
	}
}

func TestServiceMetadataRequiresAdminTokenWhenConfigured(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			AdminToken: "admin-token",
			Services: config.ServicesConfig{
				"mock-dex-api": {
					Hosts: []config.ServiceHostRule{{Host: "mock-api.local"}},
					OAuth: &config.ServiceOAuthConfig{
						ClientID:     "client-id",
						ClientSecret: "client-secret",
						AuthURL:      "http://dex.example/dex/auth",
						TokenURL:     "http://dex.example/dex/token",
					},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/services/mock-dex-api/metadata", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status without token: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/services/mock-dex-api/metadata", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status with token: %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServiceMetadataDisabledWithoutResolvedAdminToken(t *testing.T) {
	t.Setenv("SCIA_EMPTY_ADMIN_TOKEN", "")
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			AdminToken: "env:SCIA_EMPTY_ADMIN_TOKEN",
			Services: config.ServicesConfig{
				"mock-dex-api": {
					Hosts: []config.ServiceHostRule{{Host: "mock-api.local"}},
					OAuth: &config.ServiceOAuthConfig{
						ClientID:     "client-id",
						ClientSecret: "client-secret",
						AuthURL:      "http://dex.example/dex/auth",
						TokenURL:     "http://dex.example/dex/token",
					},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/services/mock-dex-api/metadata", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
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
					"client_id":     "client-id",
					"client_secret": "client-secret",
					"scope":         "https://www.googleapis.com/auth/calendar",
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

func TestGenericOAuthStartRedirectsWithServiceConfig(t *testing.T) {
	scopeName := "scope"
	openIDEnabled := true
	emailEnabled := true
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Integrations: map[string]config.OAuthIntegrationMetadataConfig{
					"mock-dex-api": {
						Scopes: []config.OAuthIntegrationScopeConfig{
							{ID: "openid", Value: "openid", Enabled: &openIDEnabled},
							{ID: "email", Value: "email", Enabled: &emailEnabled},
						},
					},
				},
			},
			Services: config.ServicesConfig{
				"mock-dex-api": {
					Hosts: []config.ServiceHostRule{{Host: "mock-api.local"}},
					OAuth: &config.ServiceOAuthConfig{
						CredentialID:        "mock-dex-api",
						ClientID:            "client-id",
						ClientSecret:        "client-secret",
						AuthURL:             "http://dex.example/dex/auth",
						TokenURL:            "http://dex.example/dex/token",
						RedirectURL:         "http://localhost:8081/oauth/mock-dex-api/callback",
						ScopeParam:          config.ScopeParamConfig{Name: &scopeName, Separator: " "},
						AuthorizationParams: map[string]string{"prompt": "login"},
					},
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/mock-dex-api/start", nil)
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
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != "http://dex.example/dex/auth" {
		t.Fatalf("unexpected redirect: %s", location)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "client-id")
	assertQueryValue(t, query, "redirect_uri", "http://localhost:8081/oauth/mock-dex-api/callback")
	assertQueryValue(t, query, "response_type", "code")
	assertQueryValue(t, query, "scope", "openid email")
	assertQueryValue(t, query, "prompt", "login")
	if query.Get("state") == "" {
		t.Fatal("missing state")
	}
}

func TestGenericOAuthCallbackStoresTokenFields(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "authorization_code")
		assertFormValue(t, r, "client_id", "client-id")
		assertFormValue(t, r, "client_secret", "client-secret")
		assertFormValue(t, r, "code", "auth-code")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"id_token":      "id-token",
			"refresh_token": "refresh-token",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Services: config.ServicesConfig{
				"mock-dex-api": {
					Hosts: []config.ServiceHostRule{{Host: "mock-api.local"}},
					OAuth: &config.ServiceOAuthConfig{
						CredentialID: "mock-dex-api",
						ClientID:     "client-id",
						ClientSecret: "client-secret",
						AuthURL:      "http://dex.example/dex/auth",
						TokenURL:     tokenEndpoint.URL,
						TokenRequest: config.TokenRequestConfig{BodyFormat: "form", ClientAuth: "body"},
					},
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "mock-dex-api", RedirectURI: "http://localhost:8081/oauth/mock-dex-api/callback", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/mock-dex-api/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	for key, want := range map[string]string{"access_token": "access-token", "id_token": "id-token", "refresh_token": "refresh-token"} {
		got, ok, err := secretStore.Get(context.Background(), "mock-dex-api", key)
		if err != nil || !ok || got != want {
			t.Fatalf("%s not stored: got=%q ok=%v err=%v", key, got, ok, err)
		}
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

func TestSlackOAuthStartRedirectsToSlack(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Slack: config.SlackOAuthConfig{
					CredentialID: "slack",
					ClientID:     "slack-client-id",
					ClientSecret: "slack-client-secret",
					Scope:        "users:read chat:write",
					RedirectURL:  "http://localhost:8081/oauth/slack/callback",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/slack/start?credential=slack", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, slackAuthURL+"?") {
		t.Fatalf("unexpected redirect: %s", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "slack-client-id")
	assertQueryValue(t, query, "scope", "users:read chat:write")
	assertQueryValue(t, query, "redirect_uri", "http://localhost:8081/oauth/slack/callback")
	if query.Get("state") == "" {
		t.Fatal("missing state")
	}
}

func TestGitHubOAuthStartRedirectsToGitHub(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				GitHub: config.GitHubOAuthConfig{
					CredentialID: "github",
					ClientID:     "github-client-id",
					ClientSecret: "github-client-secret",
					Scope:        "repo read:user",
					RedirectURL:  "http://localhost:8081/oauth/github/callback",
				},
			},
		},
	})
	srv := NewServer(store, secrets.NoopStore{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/github/start?credential=github", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, githubAuthURL+"?") {
		t.Fatalf("unexpected redirect: %s", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQueryValue(t, query, "client_id", "github-client-id")
	assertQueryValue(t, query, "scope", "repo read:user")
	assertQueryValue(t, query, "redirect_uri", "http://localhost:8081/oauth/github/callback")
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

func TestTodoistOAuthTokenExchangesRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "grant_type", "refresh_token")
		assertFormValue(t, r, "client_id", "todoist-client-id")
		assertFormValue(t, r, "client_secret", "todoist-client-secret")
		assertFormValue(t, r, "refresh_token", "todoist-refresh-token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "todoist-access-token",
			"refresh_token": "rotated-refresh-token",
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
	srv := NewServer(store, newMemorySecretStore(), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/todoist/token", strings.NewReader("credential=todoist&grant_type=refresh_token&refresh_token=todoist-refresh-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var got tokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "todoist-access-token" || got.RefreshToken != "rotated-refresh-token" {
		t.Fatalf("unexpected token response: %+v", got)
	}
}

func TestSlackOAuthCallbackStoresRefreshToken(t *testing.T) {
	ok := true
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "code", "auth-code")
		assertFormValue(t, r, "client_id", "slack-client-id")
		assertFormValue(t, r, "client_secret", "slack-client-secret")
		assertFormValue(t, r, "redirect_uri", "http://localhost:8081/oauth/slack/callback")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":            ok,
			"access_token":  "slack-access-token",
			"refresh_token": "slack-refresh-token",
			"token_type":    "user",
			"expires_in":    3600,
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Slack: config.SlackOAuthConfig{
					CredentialID: "slack",
					ClientID:     "slack-client-id",
					ClientSecret: "slack-client-secret",
					TokenURL:     tokenEndpoint.URL,
					RedirectURL:  "http://localhost:8081/oauth/slack/callback",
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "slack", RedirectURI: "http://localhost:8081/oauth/slack/callback", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/slack/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "slack", "refresh_token"); err != nil || !ok || got != "slack-refresh-token" {
		t.Fatalf("refresh token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestGitHubOAuthCallbackStoresAccessToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("unexpected accept header: %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertFormValue(t, r, "code", "auth-code")
		assertFormValue(t, r, "client_id", "github-client-id")
		assertFormValue(t, r, "client_secret", "github-client-secret")
		assertFormValue(t, r, "redirect_uri", "http://localhost:8081/oauth/github/callback")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "github-access-token",
			"token_type":   "bearer",
		})
	}))
	defer tokenEndpoint.Close()

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				GitHub: config.GitHubOAuthConfig{
					CredentialID: "github",
					ClientID:     "github-client-id",
					ClientSecret: "github-client-secret",
					TokenURL:     tokenEndpoint.URL,
					RedirectURL:  "http://localhost:8081/oauth/github/callback",
				},
			},
		},
	})
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	state := "test-state"
	srv.states.Store(state, stateInfo{CredentialID: "github", RedirectURI: "http://localhost:8081/oauth/github/callback", CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodGet, "/oauth/github/callback?state="+state+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "github", "access_token"); err != nil || !ok || got != "github-access-token" {
		t.Fatalf("access token not stored: got=%q ok=%v err=%v", got, ok, err)
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
	if got, ok, err := secretStore.Get(context.Background(), "alice", "google-calendar.refresh_token"); err != nil || !ok || got != "k8s-refresh-token" {
		t.Fatalf("refresh token not stored for user: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestGoogleOAuthTokenExchangesRefreshToken(t *testing.T) {
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
	})
	srv := NewServer(store, newMemorySecretStore(), slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/google/token", strings.NewReader("credential=google-calendar&grant_type=refresh_token&refresh_token=refresh-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var got tokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "google-access-token" {
		t.Fatalf("unexpected access token: %q", got.AccessToken)
	}
}

func TestGoogleOAuthTokenRejectsMismatchedDynamicUserToken(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{
				Mode: "kubernetes",
				Kubernetes: config.KubernetesSecretsConfig{
					DynamicUsers: true,
				},
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
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "bob", dynamicUserTokenSecretKey, "token-1"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/oauth/google/token?user_token=token-2", strings.NewReader("credential=google-calendar&user=bob&refresh_token=refresh-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
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

func TestGoogleOAuthStartAllowsDynamicUserInKubernetesMode(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{
				Mode: "kubernetes",
				Kubernetes: config.KubernetesSecretsConfig{
					DynamicUsers: true,
				},
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
	secretStore := newMemorySecretStore()
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar&user=bob&user_token=token-1", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if got, ok, err := secretStore.Get(context.Background(), "bob", dynamicUserTokenSecretKey); err != nil || !ok || got != "token-1" {
		t.Fatalf("dynamic user token not stored: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestGoogleOAuthStartRequiresDynamicUserToken(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{
				Mode: "kubernetes",
				Kubernetes: config.KubernetesSecretsConfig{
					DynamicUsers: true,
				},
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
	srv := NewServer(store, newMemorySecretStore(), slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar&user=bob", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGoogleOAuthStartRejectsMismatchedDynamicUserToken(t *testing.T) {
	store := newOAuthTestStore(t, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{
				Mode: "kubernetes",
				Kubernetes: config.KubernetesSecretsConfig{
					DynamicUsers: true,
				},
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
	secretStore := newMemorySecretStore()
	if err := secretStore.Put(context.Background(), "bob", dynamicUserTokenSecretKey, "token-1"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, secretStore, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar&user=bob&user_token=token-2", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
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

func (s *memorySecretStore) Delete(_ context.Context, credentialID, key string) error {
	delete(s.values, credentialID+":"+key)
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
