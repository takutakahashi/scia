package config

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsUnknownCredentialReference(t *testing.T) {
	cfg := &Config{
		Rules: []RuleConfig{
			{Name: "read", Action: "allow", Credentials: []string{"missing"}},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateRejectsCredentialRuleWithoutHosts(t *testing.T) {
	cfg := &Config{
		Credentials: []CredentialConfig{{ID: "token", Type: "bearer", Value: "secret"}},
		Rules: []RuleConfig{
			{Name: "inject-all", Action: "allow", Credentials: []string{"token"}},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateRejectsCredentialRuleWildcardHosts(t *testing.T) {
	cfg := &Config{
		Credentials: []CredentialConfig{{ID: "token", Type: "bearer", Value: "secret"}},
		Rules: []RuleConfig{
			{Name: "inject-all", Hosts: []string{"*"}, Action: "allow", Credentials: []string{"token"}},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestHeaderValueFromEnv(t *testing.T) {
	t.Setenv("SCIA_TEST_SECRET", "secret-value")

	if got := HeaderValueFromEnv("env:SCIA_TEST_SECRET"); got != "secret-value" {
		t.Fatalf("unexpected env value: %q", got)
	}
	if got := HeaderValueFromEnv("literal"); got != "literal" {
		t.Fatalf("unexpected literal value: %q", got)
	}
}

func TestAdminTokenRequiresNonEmptyResolvedValue(t *testing.T) {
	t.Setenv("SCIA_EMPTY_ADMIN_TOKEN", "")
	t.Setenv("SCIA_ADMIN_TOKEN", "secret-token")

	if token, ok := AdminToken(""); ok || token != "" {
		t.Fatalf("unexpected empty literal token: token=%q ok=%v", token, ok)
	}
	if token, ok := AdminToken("env:SCIA_EMPTY_ADMIN_TOKEN"); ok || token != "" {
		t.Fatalf("unexpected empty env token: token=%q ok=%v", token, ok)
	}
	if token, ok := AdminToken("env:SCIA_ADMIN_TOKEN"); !ok || token != "secret-token" {
		t.Fatalf("unexpected env token: token=%q ok=%v", token, ok)
	}
}

func TestIsAuthorizedBearerToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret-token")

	if !IsAuthorizedBearerToken(req, "secret-token") {
		t.Fatal("expected bearer token to authorize")
	}
	if IsAuthorizedBearerToken(req, "") {
		t.Fatal("empty admin token must not authorize")
	}
	if IsAuthorizedBearerToken(req, "other-token") {
		t.Fatal("wrong bearer token authorized")
	}
}

func TestValidateExpandsEnvInAllStringFields(t *testing.T) {
	t.Setenv("SCIA_TEST_SERVICE_NAME", "Calendar")
	t.Setenv("SCIA_TEST_HOST", "api.example.com")
	t.Setenv("SCIA_TEST_CLIENT_ID", "client-id")
	t.Setenv("SCIA_TEST_CLIENT_SECRET", "client-secret")
	t.Setenv("SCIA_TEST_AUTH_URL", "https://auth.example.com/oauth/authorize")
	t.Setenv("SCIA_TEST_TOKEN_URL", "https://auth.example.com/oauth/token")
	t.Setenv("SCIA_TEST_SCOPE_NAME", "requested_scope")
	t.Setenv("SCIA_TEST_SUCCESS_FIELD", "access_token")
	t.Setenv("SCIA_TEST_AUTH_PARAM", "offline")
	t.Setenv("SCIA_TEST_HEADER_NAME", "X-API-Key")
	t.Setenv("SCIA_TEST_HEADER_VALUE", "{{ secret \"api-key\" }}")
	t.Setenv("SCIA_TEST_RULE_NAME", "calendar-read")

	scopeName := "env:SCIA_TEST_SCOPE_NAME"
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"calendar": {
					Name: "env:SCIA_TEST_SERVICE_NAME",
					Hosts: []ServiceHostRule{
						{Host: "env:SCIA_TEST_HOST"},
					},
					OAuth: &ServiceOAuthConfig{
						ClientID:     "env:SCIA_TEST_CLIENT_ID",
						ClientSecret: "env:SCIA_TEST_CLIENT_SECRET",
						AuthURL:      "env:SCIA_TEST_AUTH_URL",
						TokenURL:     "env:SCIA_TEST_TOKEN_URL",
						ScopeParam: ScopeParamConfig{
							Name: &scopeName,
						},
						AuthorizationParams: map[string]string{
							"access_type": "env:SCIA_TEST_AUTH_PARAM",
						},
						TokenRequest: TokenRequestConfig{
							SuccessField: "env:SCIA_TEST_SUCCESS_FIELD",
						},
					},
					Injection: ServiceInjectionConfig{
						Headers: []InjectionTemplate{
							{Name: "env:SCIA_TEST_HEADER_NAME", Value: "env:SCIA_TEST_HEADER_VALUE"},
						},
					},
				},
			},
		},
		Rules: []RuleConfig{
			{Name: "env:SCIA_TEST_RULE_NAME", Action: "allow", Services: []string{"calendar"}},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	service := cfg.Server.Services["calendar"]
	if service.Name != "Calendar" {
		t.Fatalf("service name was not expanded: %q", service.Name)
	}
	if service.Hosts[0].Host != "api.example.com" {
		t.Fatalf("host was not expanded: %q", service.Hosts[0].Host)
	}
	if service.OAuth.ClientID != "client-id" || service.OAuth.ClientSecret != "client-secret" {
		t.Fatalf("oauth client config was not expanded: %#v", service.OAuth)
	}
	if service.OAuth.AuthURL != "https://auth.example.com/oauth/authorize" || service.OAuth.TokenURL != "https://auth.example.com/oauth/token" {
		t.Fatalf("oauth URL config was not expanded: %#v", service.OAuth)
	}
	if service.OAuth.ScopeParamName() != "requested_scope" {
		t.Fatalf("scope param name was not expanded: %q", service.OAuth.ScopeParamName())
	}
	if service.OAuth.AuthorizationParams["access_type"] != "offline" {
		t.Fatalf("authorization param was not expanded: %q", service.OAuth.AuthorizationParams["access_type"])
	}
	if service.OAuth.TokenRequest.SuccessField != "access_token" {
		t.Fatalf("token request field was not expanded: %q", service.OAuth.TokenRequest.SuccessField)
	}
	if service.Injection.Headers[0].Name != "X-API-Key" || service.Injection.Headers[0].Value != "{{ secret \"api-key\" }}" {
		t.Fatalf("injection template was not expanded: %#v", service.Injection.Headers[0])
	}
	if cfg.Rules[0].Name != "calendar-read" {
		t.Fatalf("rule name was not expanded: %q", cfg.Rules[0].Name)
	}
}

func TestValidateDefaultsServerModeToProxy(t *testing.T) {
	cfg := &Config{}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Mode != "proxy" {
		t.Fatalf("unexpected server mode: %q", cfg.Server.Mode)
	}
}

func TestValidateRejectsUnknownServerMode(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Mode: "all"}}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateExternalSecretsModeRequiresWebhookConfig(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Secrets: SecretsConfig{Mode: "external"},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateExternalSecretsModeAcceptsWebhookConfig(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Secrets: SecretsConfig{
				Mode: "external",
				External: ExternalSecretsConfig{
					Webhook: ExternalSecretsWebhookConfig{
						URL:       "https://secrets.example.com/hooks/scia",
						SecretKey: "shared-webhook-key",
					},
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRequiresUsersForKubernetesMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Secrets: SecretsConfig{Mode: "kubernetes"},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateAllowsDynamicUsersForKubernetesMode(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Secrets: SecretsConfig{
				Mode: "kubernetes",
				Kubernetes: KubernetesSecretsConfig{
					DynamicUsers: true,
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.HasUser("alice") {
		t.Fatal("expected dynamic user to be accepted")
	}
	if cfg.HasUser("Alice") {
		t.Fatal("expected invalid dynamic user to be rejected")
	}
	if cfg.Server.Secrets.Kubernetes.DynamicUserSecretNamePrefix != "scia-oauth-" {
		t.Fatalf("unexpected dynamic user secret prefix: %q", cfg.Server.Secrets.Kubernetes.DynamicUserSecretNamePrefix)
	}
}

func TestCredentialUserID(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Users: map[string]UserConfig{
				"alice": {SecretName: "scia-oauth-alice"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	cred := CredentialConfig{
		ID:   "alice.google-calendar",
		Type: "google-oauth-refresh-token",
	}
	if got := CredentialUserID(cfg, cred); got != "alice" {
		t.Fatalf("unexpected user id: %q", got)
	}

	credWithParam := CredentialConfig{
		ID:     "google-calendar",
		Type:   "google-oauth-refresh-token",
		Params: map[string]string{"user": "alice"},
	}
	if got := CredentialUserID(cfg, credWithParam); got != "alice" {
		t.Fatalf("unexpected user id from params: %q", got)
	}
}

func TestSecretRefParts(t *testing.T) {
	credentialID, key, err := SecretRefParts("service-a.google.client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if credentialID != "service-a.google" || key != "client-secret" {
		t.Fatalf("unexpected secret ref parts: credentialID=%q key=%q", credentialID, key)
	}
}

func TestFileProviderMergesMultipleYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	override := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(base, []byte(`
server:
  services:
    google-calendar:
      hosts:
        - host: www.googleapis.com
          pathPrefix: /calendar/
      oauth:
        credentialId: google-calendar
        clientId: base-client
        clientSecret: base-secret
        authUrl: https://accounts.google.com/o/oauth2/v2/auth
        tokenUrl: https://oauth2.googleapis.com/token
rules:
  - name: base
    action: allow
    services: ["google-calendar"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(override, []byte(`
server:
  services:
    google-calendar:
      oauth:
        clientId: override-client
`), 0o600); err != nil {
		t.Fatal(err)
	}

	provider := NewFileProviderPaths([]string{base, override}, slog.Default())
	cfg, err := provider.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	service := cfg.Server.Services["google-calendar"]
	if service.OAuth.ClientID != "override-client" {
		t.Fatalf("override did not win: %q", service.OAuth.ClientID)
	}
	if service.OAuth.ClientSecret != "base-secret" {
		t.Fatalf("base value was not preserved: %q", service.OAuth.ClientSecret)
	}
	if len(service.Hosts) != 1 || service.Hosts[0].AuthMethod != "bearer" {
		t.Fatalf("unexpected merged hosts/defaults: %#v", service.Hosts)
	}
}

func TestValidateAllowsRuleServices(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"mock": {
					Hosts: []ServiceHostRule{{Host: "api.example.com", AuthMethod: "none"}},
				},
			},
		},
		Rules: []RuleConfig{{Name: "mock", Action: "allow", Services: []string{"mock"}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAcceptsParameterServiceInputs(t *testing.T) {
	released := true
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"example-api": {
					Name:        "Example API",
					Description: "Connect with a personal access token.",
					Released:    &released,
					Inputs: []ServiceInputConfig{
						{ID: "token", Name: "Personal access token", Description: "Token issued by Example API.", Type: "secret", Required: true, SecretKey: "access_token"},
					},
					Hosts: []ServiceHostRule{{Host: "api.example.com", AuthMethod: "bearer"}},
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	service := cfg.Server.Services["example-api"]
	if !service.ParameterService() {
		t.Fatalf("expected parameter service")
	}
	if keys := service.InputSecretKeys(); len(keys) != 1 || keys[0] != "access_token" {
		t.Fatalf("unexpected input secret keys: %#v", keys)
	}
}

func TestValidateRejectsParameterServiceWithOAuth(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"example-api": {
					Inputs: []ServiceInputConfig{{ID: "token", Type: "secret", SecretKey: "access_token"}},
					Hosts:  []ServiceHostRule{{Host: "api.example.com"}},
					OAuth:  &ServiceOAuthConfig{AuthURL: "http://example.com/auth", TokenURL: "http://example.com/token", ClientID: "id", ClientSecret: "secret"},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error combining inputs with oauth")
	}
}

func TestValidateRejectsBearerParameterServiceWithoutAccessTokenInput(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Services: ServicesConfig{
		"example-api": {
			Inputs: []ServiceInputConfig{{ID: "token", Type: "secret", SecretKey: "api_key"}},
			Hosts:  []ServiceHostRule{{Host: "api.example.com", AuthMethod: "bearer"}},
		},
	}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "access_token") {
		t.Fatalf("expected access_token validation error, got %v", err)
	}
}

func TestValidateRejectsDuplicateInputIDs(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"example-api": {
					Inputs: []ServiceInputConfig{
						{ID: "token", Type: "secret", SecretKey: "access_token"},
						{ID: "token", Type: "secret", SecretKey: "api_key"},
					},
					Hosts: []ServiceHostRule{{Host: "api.example.com"}},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected duplicate input id error")
	}
}

func TestValidateRejectsDuplicateInputSecretKeys(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"example-api": {
					Inputs: []ServiceInputConfig{
						{ID: "token", Type: "secret", SecretKey: "access_token"},
						{ID: "token2", Type: "secret", SecretKey: "access_token"},
					},
					Hosts: []ServiceHostRule{{Host: "api.example.com"}},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected duplicate secret key error")
	}
}

func TestValidateRejectsUnsupportedInputType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"example-api": {
					Inputs: []ServiceInputConfig{{ID: "token", Type: "opaque", SecretKey: "access_token"}},
					Hosts:  []ServiceHostRule{{Host: "api.example.com"}},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected unsupported type error")
	}
}

func TestValidateRejectsSecretInputWithoutSecretKey(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Services: ServicesConfig{
				"example-api": {
					Inputs: []ServiceInputConfig{{ID: "token", Type: "secret"}},
					Hosts:  []ServiceHostRule{{Host: "api.example.com"}},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected missing secretKey error")
	}
}
