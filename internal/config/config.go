package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

type Provider interface {
	Load(context.Context) (*Config, error)
	Watch(context.Context, chan<- *Config) error
}

type Store struct {
	current atomic.Pointer[Config]
}

func NewStore(ctx context.Context, provider Provider, logger *slog.Logger) (*Store, error) {
	cfg, err := provider.Load(ctx)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	store := &Store{}
	store.current.Store(cfg)

	updates := make(chan *Config, 1)
	go func() {
		if err := provider.Watch(ctx, updates); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("config watcher stopped", "error", err)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case next := <-updates:
				if err := next.Validate(); err != nil {
					logger.Error("ignoring invalid config reload", "error", err)
					continue
				}
				store.current.Store(next)
				logger.Info("config reloaded")
			}
		}
	}()

	return store, nil
}

func (s *Store) Get() *Config {
	return s.current.Load()
}

type Config struct {
	Server      ServerConfig       `yaml:"server"`
	Credentials []CredentialConfig `yaml:"credentials"`
	Rules       []RuleConfig       `yaml:"rules"`
}

type ServerConfig struct {
	Listen          string             `yaml:"listen"`
	AdminToken      string             `yaml:"adminToken"`
	ApprovalTimeout Duration           `yaml:"approvalTimeout"`
	MITM            MITMConfig         `yaml:"mitm"`
	BackendProxy    BackendProxyConfig `yaml:"backendProxy"`
	OAuth           OAuthConfig        `yaml:"oauth"`
	Secrets         SecretsConfig      `yaml:"secrets"`
}

type MITMConfig struct {
	CACertPath string `yaml:"caCertPath"`
	CAKeyPath  string `yaml:"caKeyPath"`
}

type BackendProxyConfig struct {
	URL string `yaml:"url"`
}

type OAuthConfig struct {
	Listen      string                          `yaml:"listen"`
	RedirectURL string                          `yaml:"redirectUrl"`
	Google      GoogleOAuthConfig               `yaml:"google"`
	Namespaces  map[string]OAuthNamespaceConfig `yaml:"namespaces"`
}

type GoogleOAuthConfig struct {
	CredentialID      string `yaml:"credentialId"`
	ClientID          string `yaml:"clientId"`
	ClientIDSecretRef string `yaml:"clientIdSecretRef"`
	ClientSecret      string `yaml:"clientSecret"`
	ClientSecretRef   string `yaml:"clientSecretRef"`
	Scope             string `yaml:"scope"`
	AuthURL           string `yaml:"authUrl"`
	TokenURL          string `yaml:"tokenUrl"`
	RevokeURL         string `yaml:"revokeUrl"`
	RedirectURL       string `yaml:"redirectUrl"`
}

type OAuthNamespaceConfig struct {
	Google GoogleOAuthConfig `yaml:"google"`
}

type SecretsConfig struct {
	SQLitePath string `yaml:"sqlitePath"`
}

type CredentialConfig struct {
	ID     string            `yaml:"id"`
	Type   string            `yaml:"type"`
	Header string            `yaml:"header"`
	Value  string            `yaml:"value"`
	Params map[string]string `yaml:"params"`
}

type RuleConfig struct {
	Name         string   `yaml:"name"`
	Hosts        []string `yaml:"hosts"`
	Methods      []string `yaml:"methods"`
	Paths        []string `yaml:"paths"`
	Action       string   `yaml:"action"`
	Credentials  []string `yaml:"credentials"`
	ApprovalNote string   `yaml:"approvalNote"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func (c *Config) Validate() error {
	if c.Server.ApprovalTimeout.Duration == 0 {
		c.Server.ApprovalTimeout.Duration = 5 * time.Minute
	}
	if c.Server.MITM.CACertPath == "" {
		c.Server.MITM.CACertPath = "data/scia-ca.pem"
	}
	if c.Server.MITM.CAKeyPath == "" {
		c.Server.MITM.CAKeyPath = "data/scia-ca-key.pem"
	}
	if c.Server.Secrets.SQLitePath == "" {
		c.Server.Secrets.SQLitePath = "data/scia-secrets.db"
	}
	if rawBackendProxyURL := HeaderValueFromEnv(c.Server.BackendProxy.URL); rawBackendProxyURL != "" {
		parsed, err := url.Parse(rawBackendProxyURL)
		if err != nil {
			return fmt.Errorf("server.backendProxy.url is invalid: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("server.backendProxy.url must use http or https scheme")
		}
		if parsed.Host == "" {
			return fmt.Errorf("server.backendProxy.url must include a host")
		}
	}
	seenCreds := map[string]struct{}{}
	for i, cred := range c.Credentials {
		if cred.ID == "" {
			return fmt.Errorf("credentials[%d].id is required", i)
		}
		if _, ok := seenCreds[cred.ID]; ok {
			return fmt.Errorf("duplicate credential id %q", cred.ID)
		}
		seenCreds[cred.ID] = struct{}{}
		switch cred.Type {
		case "bearer", "basic", "static-header", "oauth2-client-credentials", "google-oauth-refresh-token":
		default:
			return fmt.Errorf("credential %q has unsupported type %q", cred.ID, cred.Type)
		}
		if cred.Type == "static-header" && cred.Header == "" {
			return fmt.Errorf("credential %q requires header", cred.ID)
		}
	}
	if c.Server.OAuth.Google.HasClientConfig() {
		seenCreds[c.GoogleOAuthCredentialID()] = struct{}{}
	}
	for namespace, ns := range c.Server.OAuth.Namespaces {
		if namespace == "" {
			return fmt.Errorf("server.oauth.namespaces cannot include an empty namespace")
		}
		if strings.Contains(namespace, ".") {
			return fmt.Errorf("server.oauth.namespaces[%q] cannot contain dots", namespace)
		}
		if ns.Google.HasClientConfig() {
			seenCreds[NamespaceGoogleCredentialID(namespace)] = struct{}{}
		}
	}
	for i, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rules[%d].name is required", i)
		}
		switch rule.Action {
		case "allow", "deny", "approval":
		default:
			return fmt.Errorf("rule %q has unsupported action %q", rule.Name, rule.Action)
		}
		for _, credentialID := range rule.Credentials {
			if _, ok := seenCreds[credentialID]; !ok {
				return fmt.Errorf("rule %q references unknown credential %q", rule.Name, credentialID)
			}
		}
	}
	return nil
}

func CredentialByID(cfg *Config, id string) (CredentialConfig, bool) {
	for _, cred := range cfg.Credentials {
		if cred.ID == id {
			return cred, true
		}
	}
	if cfg.Server.OAuth.Google.HasClientConfig() && id == cfg.GoogleOAuthCredentialID() {
		return CredentialConfig{ID: id, Type: "google-oauth-refresh-token", Params: map[string]string{}}, true
	}
	if namespace, ok := GoogleCredentialNamespace(id); ok {
		if ns, exists := cfg.Server.OAuth.Namespaces[namespace]; exists && ns.Google.HasClientConfig() {
			return CredentialConfig{ID: id, Type: "google-oauth-refresh-token", Params: map[string]string{}}, true
		}
	}
	return CredentialConfig{}, false
}

func (c *Config) GoogleOAuthCredentialID() string {
	if c.Server.OAuth.Google.CredentialID != "" {
		return c.Server.OAuth.Google.CredentialID
	}
	return "google"
}

func (g GoogleOAuthConfig) HasClientConfig() bool {
	return (g.ClientID != "" || g.ClientIDSecretRef != "") && (g.ClientSecret != "" || g.ClientSecretRef != "")
}

func GoogleCredentialNamespace(id string) (string, bool) {
	namespace, provider, ok := strings.Cut(id, ".")
	if !ok || namespace == "" || provider != "google" {
		return "", false
	}
	return namespace, true
}

func NamespaceGoogleCredentialID(namespace string) string {
	return namespace + ".google"
}

func GoogleOAuthConfigForCredential(cfg *Config, credentialID string) (GoogleOAuthConfig, bool) {
	if credentialID == "" || credentialID == cfg.GoogleOAuthCredentialID() {
		if cfg.Server.OAuth.Google.HasClientConfig() {
			return cfg.Server.OAuth.Google, true
		}
		return GoogleOAuthConfig{}, false
	}
	if namespace, ok := GoogleCredentialNamespace(credentialID); ok {
		ns, exists := cfg.Server.OAuth.Namespaces[namespace]
		if exists && ns.Google.HasClientConfig() {
			return ns.Google, true
		}
	}
	return GoogleOAuthConfig{}, false
}

func SecretRefParts(ref string) (string, string, error) {
	namespace, rest, ok := strings.Cut(ref, ".")
	if !ok || namespace == "" {
		return "", "", fmt.Errorf("secret ref %q must be formatted as namespace.provider.key", ref)
	}
	provider, key, ok := strings.Cut(rest, ".")
	if !ok || provider == "" || key == "" {
		return "", "", fmt.Errorf("secret ref %q must be formatted as namespace.provider.key", ref)
	}
	return namespace + "." + provider, key, nil
}

func CloneRequestWithoutProxyHeaders(r *http.Request) *http.Request {
	next := r.Clone(r.Context())
	next.RequestURI = ""
	next.Header = r.Header.Clone()
	for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "Connection", "Keep-Alive"} {
		next.Header.Del(name)
	}
	return next
}

func TargetURL(r *http.Request) (*url.URL, error) {
	if r.URL == nil {
		return nil, errors.New("missing request URL")
	}
	if r.URL.IsAbs() {
		return r.URL, nil
	}
	if r.Host == "" {
		return nil, errors.New("missing host")
	}
	scheme := "http"
	return &url.URL{Scheme: scheme, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}, nil
}

func HeaderValueFromEnv(value string) string {
	if strings.HasPrefix(value, "env:") {
		return os.Getenv(strings.TrimPrefix(value, "env:"))
	}
	return value
}
