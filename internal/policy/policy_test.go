package policy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/takutakahashi/scia/internal/config"
)

func TestEvaluateFirstMatchingRule(t *testing.T) {
	cfg := &config.Config{Rules: []config.RuleConfig{
		{Name: "deny-delete", Hosts: []string{"api.example.com"}, Methods: []string{"DELETE"}, Paths: []string{"/admin/*"}, Action: "deny"},
		{Name: "allow-all", Action: "allow", Credentials: []string{"token"}},
	}}
	req := &http.Request{Method: http.MethodDelete, URL: &url.URL{Path: "/admin/users"}}

	decision := Evaluate(cfg, req, "api.example.com")
	if decision.Action != "deny" || decision.Rule.Name != "deny-delete" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestEvaluateDefaultsToAllow(t *testing.T) {
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/v1/items"}}

	decision := Evaluate(&config.Config{}, req, "api.example.com")
	if decision.Action != "allow" {
		t.Fatalf("expected default allow, got %q", decision.Action)
	}
}
