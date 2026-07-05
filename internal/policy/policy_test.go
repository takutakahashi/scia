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

func TestEvaluateTrailingWildcardMatchesNestedPath(t *testing.T) {
	cfg := &config.Config{Rules: []config.RuleConfig{
		{Name: "inject-calendar", Hosts: []string{"www.googleapis.com"}, Methods: []string{"GET"}, Paths: []string{"/calendar/v3/*"}, Action: "allow", Credentials: []string{"google-calendar"}},
	}}
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/calendar/v3/users/me/calendarList"}}

	decision := Evaluate(cfg, req, "www.googleapis.com")
	if len(decision.Credentials) != 1 || decision.Credentials[0] != "google-calendar" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestEvaluateNormalizesRequestPath(t *testing.T) {
	cfg := &config.Config{Rules: []config.RuleConfig{
		{Name: "deny-admin", Methods: []string{"GET"}, Paths: []string{"/admin/*"}, Action: "deny"},
		{Name: "allow-all", Action: "allow"},
	}}

	for _, rawPath := range []string{"/public/../admin/secret", "/./admin/secret", "//admin/secret"} {
		req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: rawPath}}
		decision := Evaluate(cfg, req, "api.example.com")
		if decision.Action != "deny" {
			t.Fatalf("path %q was not denied: %#v", rawPath, decision)
		}
	}
}

func TestEvaluateNormalizesTrailingSlashForExactPath(t *testing.T) {
	cfg := &config.Config{Rules: []config.RuleConfig{
		{Name: "deny-secret", Methods: []string{"GET"}, Paths: []string{"/secret"}, Action: "deny"},
		{Name: "allow-all", Action: "allow"},
	}}
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/secret/"}}

	decision := Evaluate(cfg, req, "api.example.com")
	if decision.Action != "deny" {
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
