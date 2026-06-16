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
