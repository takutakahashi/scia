package policy

import (
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/takutakahashi/scia/internal/config"
)

type Decision struct {
	Rule        config.RuleConfig
	Action      string
	Credentials []string
	Services    []string
}

func Evaluate(cfg *config.Config, r *http.Request, targetHost string) Decision {
	for _, rule := range cfg.Rules {
		if ruleMatches(rule, r.Method, targetHost, r.URL.Path) {
			return Decision{Rule: rule, Action: rule.Action, Credentials: rule.Credentials, Services: rule.Services}
		}
	}
	return Decision{Action: "allow"}
}

func ruleMatches(rule config.RuleConfig, method, host, reqPath string) bool {
	if len(rule.Methods) > 0 && !containsFold(rule.Methods, method) {
		return false
	}
	if len(rule.Hosts) > 0 && !matchHostAny(rule.Hosts, host) {
		return false
	}
	if len(rule.Paths) > 0 && !matchAny(rule.Paths, reqPath) {
		return false
	}
	return true
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func matchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if matchOne(pattern, strings.ToLower(value)) {
			return true
		}
	}
	return false
}

func matchHostAny(patterns []string, host string) bool {
	normalized := strings.ToLower(host)
	hostOnly := normalized
	if splitHost, _, err := net.SplitHostPort(normalized); err == nil {
		hostOnly = splitHost
	}
	for _, pattern := range patterns {
		if matchOne(pattern, normalized) || matchOne(pattern, hostOnly) {
			return true
		}
	}
	return false
}

func matchOne(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	matched, err := path.Match(pattern, value)
	if err == nil && matched {
		return true
	}
	if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(value, strings.TrimSuffix(pattern, "*")) {
		return true
	}
	return pattern == value
}
