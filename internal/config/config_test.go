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
