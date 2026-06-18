package config

import "testing"

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

func TestHeaderValueFromEnv(t *testing.T) {
	t.Setenv("SCIA_TEST_SECRET", "secret-value")

	if got := HeaderValueFromEnv("env:SCIA_TEST_SECRET"); got != "secret-value" {
		t.Fatalf("unexpected env value: %q", got)
	}
	if got := HeaderValueFromEnv("literal"); got != "literal" {
		t.Fatalf("unexpected literal value: %q", got)
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

func TestValidateAllowsNamespacedGoogleCredentialReference(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			OAuth: OAuthConfig{
				Namespaces: map[string]OAuthNamespaceConfig{
					"service-a": {
						Google: GoogleOAuthConfig{
							ClientIDSecretRef: "service-a.google.client-id",
							ClientSecretRef:   "service-a.google.client-secret",
						},
					},
				},
			},
		},
		Rules: []RuleConfig{
			{Name: "google", Action: "allow", Credentials: []string{"service-a.google"}},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
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
