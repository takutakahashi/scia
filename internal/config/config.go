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
	Mode            string                `yaml:"mode"`
	Listen          string                `yaml:"listen"`
	AdminToken      string                `yaml:"adminToken"`
	ApprovalTimeout Duration              `yaml:"approvalTimeout"`
	MITM            MITMConfig            `yaml:"mitm"`
	BackendProxy    BackendProxyConfig    `yaml:"backendProxy"`
	Integrations    IntegrationsConfig    `yaml:"integrations"`
	OAuth           OAuthConfig           `yaml:"oauth"`
	Secrets         SecretsConfig         `yaml:"secrets"`
	Users           map[string]UserConfig `yaml:"users"`
}

type UserConfig struct {
	SecretName string `yaml:"secretName"`
}

type MITMConfig struct {
	CACertPath string `yaml:"caCertPath"`
	CAKeyPath  string `yaml:"caKeyPath"`
}

type BackendProxyConfig struct {
	URL string `yaml:"url"`
}

type IntegrationsConfig struct {
	Google  IntegrationConfig `yaml:"google"`
	Notion  IntegrationConfig `yaml:"notion"`
	Todoist IntegrationConfig `yaml:"todoist"`
	Slack   IntegrationConfig `yaml:"slack"`
	GitHub  IntegrationConfig `yaml:"github"`
}

type IntegrationConfig struct {
	Hosts []string `yaml:"hosts"`
}

type OAuthConfig struct {
	Listen       string                                    `yaml:"listen"`
	RedirectURL  string                                    `yaml:"redirectUrl"`
	Integrations map[string]OAuthIntegrationMetadataConfig `yaml:"integrations"`
	Google       GoogleOAuthConfig                         `yaml:"google"`
	Notion       NotionOAuthConfig                         `yaml:"notion"`
	Todoist      TodoistOAuthConfig                        `yaml:"todoist"`
	Slack        SlackOAuthConfig                          `yaml:"slack"`
	GitHub       GitHubOAuthConfig                         `yaml:"github"`
}

type OAuthIntegrationMetadataConfig struct {
	Name        string                        `yaml:"name"`
	IconURL     string                        `yaml:"iconUrl"`
	Description string                        `yaml:"description"`
	Released    *bool                         `yaml:"released"`
	Setup       map[string]string             `yaml:"setup"`
	Scopes      []OAuthIntegrationScopeConfig `yaml:"scopes"`
}

type OAuthIntegrationScopeConfig struct {
	ID          string `yaml:"id"`
	Value       string `yaml:"value"`
	Name        string `yaml:"name"`
	Desc        string `yaml:"desc"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
	Group       string `yaml:"group"`
	GroupName   string `yaml:"groupName"`
	GroupDesc   string `yaml:"groupDesc"`
	Enabled     *bool  `yaml:"enabled"`
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

type NotionOAuthConfig struct {
	CredentialID      string `yaml:"credentialId"`
	ClientID          string `yaml:"clientId"`
	ClientIDSecretRef string `yaml:"clientIdSecretRef"`
	ClientSecret      string `yaml:"clientSecret"`
	ClientSecretRef   string `yaml:"clientSecretRef"`
	AuthURL           string `yaml:"authUrl"`
	TokenURL          string `yaml:"tokenUrl"`
	RevokeURL         string `yaml:"revokeUrl"`
	RedirectURL       string `yaml:"redirectUrl"`
	NotionVersion     string `yaml:"notionVersion"`
}

type TodoistOAuthConfig struct {
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

type SlackOAuthConfig struct {
	CredentialID      string `yaml:"credentialId"`
	ClientID          string `yaml:"clientId"`
	ClientIDSecretRef string `yaml:"clientIdSecretRef"`
	ClientSecret      string `yaml:"clientSecret"`
	ClientSecretRef   string `yaml:"clientSecretRef"`
	Scope             string `yaml:"scope"`
	AuthURL           string `yaml:"authUrl"`
	TokenURL          string `yaml:"tokenUrl"`
	RefreshTokenURL   string `yaml:"refreshTokenUrl"`
	RevokeURL         string `yaml:"revokeUrl"`
	RedirectURL       string `yaml:"redirectUrl"`
}

type GitHubOAuthConfig struct {
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

type SecretsConfig struct {
	Mode       string                  `yaml:"mode"`
	SQLitePath string                  `yaml:"sqlitePath"`
	Kubernetes KubernetesSecretsConfig `yaml:"kubernetes"`
}

type KubernetesSecretsConfig struct {
	Namespace                   string `yaml:"namespace"`
	DynamicUsers                bool   `yaml:"dynamicUsers"`
	DynamicUserSecretNamePrefix string `yaml:"dynamicUserSecretNamePrefix"`
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
	if c.Server.Mode == "" {
		c.Server.Mode = "proxy"
	}
	switch c.Server.Mode {
	case "proxy", "oauth":
	default:
		return fmt.Errorf("server.mode must be proxy or oauth")
	}
	if c.Server.ApprovalTimeout.Duration == 0 {
		c.Server.ApprovalTimeout.Duration = 5 * time.Minute
	}
	if c.Server.MITM.CACertPath == "" {
		c.Server.MITM.CACertPath = "data/scia-ca.pem"
	}
	if c.Server.MITM.CAKeyPath == "" {
		c.Server.MITM.CAKeyPath = "data/scia-ca-key.pem"
	}
	if c.Server.Secrets.Mode == "" {
		c.Server.Secrets.Mode = "sqlite"
	}
	switch c.Server.Secrets.Mode {
	case "sqlite", "kubernetes":
	default:
		return fmt.Errorf("server.secrets.mode must be sqlite or kubernetes")
	}
	if c.Server.Secrets.SQLitePath == "" {
		c.Server.Secrets.SQLitePath = "data/scia-secrets.db"
	}
	if c.Server.Secrets.Mode == "kubernetes" {
		if c.Server.Secrets.Kubernetes.Namespace == "" {
			c.Server.Secrets.Kubernetes.Namespace = "default"
		}
		if c.Server.Secrets.Kubernetes.DynamicUserSecretNamePrefix == "" {
			c.Server.Secrets.Kubernetes.DynamicUserSecretNamePrefix = "scia-oauth-"
		}
		if !c.Server.Secrets.Kubernetes.DynamicUsers && len(c.Server.Users) == 0 {
			return fmt.Errorf("server.users is required when server.secrets.mode is kubernetes")
		}
		if c.Server.Secrets.Kubernetes.DynamicUsers && !validSecretNamePrefix(c.Server.Secrets.Kubernetes.DynamicUserSecretNamePrefix) {
			return fmt.Errorf("server.secrets.kubernetes.dynamicUserSecretNamePrefix must contain only lowercase letters, numbers, and hyphens, and start with a letter or number")
		}
		for userID, user := range c.Server.Users {
			if userID == "" {
				return fmt.Errorf("server.users cannot include an empty user id")
			}
			if user.SecretName == "" {
				return fmt.Errorf("server.users[%q].secretName is required", userID)
			}
		}
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
		case "bearer", "basic", "static-header", "oauth2-client-credentials", "google-oauth-refresh-token", "notion-oauth-refresh-token", "todoist-oauth-refresh-token", "slack-user-oauth-token", "github-oauth-token":
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
	if c.Server.OAuth.Notion.HasClientConfig() {
		seenCreds[c.NotionOAuthCredentialID()] = struct{}{}
	}
	if c.Server.OAuth.Todoist.HasClientConfig() {
		seenCreds[c.TodoistOAuthCredentialID()] = struct{}{}
	}
	if c.Server.OAuth.Slack.HasClientConfig() {
		seenCreds[c.SlackOAuthCredentialID()] = struct{}{}
	}
	if c.Server.OAuth.GitHub.HasClientConfig() {
		seenCreds[c.GitHubOAuthCredentialID()] = struct{}{}
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
	if cfg.Server.OAuth.Notion.HasClientConfig() && id == cfg.NotionOAuthCredentialID() {
		return CredentialConfig{ID: id, Type: "notion-oauth-refresh-token", Params: map[string]string{}}, true
	}
	if cfg.Server.OAuth.Todoist.HasClientConfig() && id == cfg.TodoistOAuthCredentialID() {
		return CredentialConfig{ID: id, Type: "todoist-oauth-refresh-token", Params: map[string]string{}}, true
	}
	if cfg.Server.OAuth.Slack.HasClientConfig() && id == cfg.SlackOAuthCredentialID() {
		return CredentialConfig{ID: id, Type: "slack-user-oauth-token", Params: map[string]string{}}, true
	}
	if cfg.Server.OAuth.GitHub.HasClientConfig() && id == cfg.GitHubOAuthCredentialID() {
		return CredentialConfig{ID: id, Type: "github-oauth-token", Params: map[string]string{}}, true
	}
	return CredentialConfig{}, false
}

func (c *Config) GoogleOAuthCredentialID() string {
	if c.Server.OAuth.Google.CredentialID != "" {
		return c.Server.OAuth.Google.CredentialID
	}
	return "google"
}

func (c *Config) NotionOAuthCredentialID() string {
	if c.Server.OAuth.Notion.CredentialID != "" {
		return c.Server.OAuth.Notion.CredentialID
	}
	return "notion"
}

func (c *Config) TodoistOAuthCredentialID() string {
	if c.Server.OAuth.Todoist.CredentialID != "" {
		return c.Server.OAuth.Todoist.CredentialID
	}
	return "todoist"
}

func (c *Config) SlackOAuthCredentialID() string {
	if c.Server.OAuth.Slack.CredentialID != "" {
		return c.Server.OAuth.Slack.CredentialID
	}
	return "slack"
}

func (c *Config) GitHubOAuthCredentialID() string {
	if c.Server.OAuth.GitHub.CredentialID != "" {
		return c.Server.OAuth.GitHub.CredentialID
	}
	return "github"
}

func (g GoogleOAuthConfig) HasClientConfig() bool {
	return (g.ClientID != "" || g.ClientIDSecretRef != "") && (g.ClientSecret != "" || g.ClientSecretRef != "")
}

func (n NotionOAuthConfig) HasClientConfig() bool {
	return (n.ClientID != "" || n.ClientIDSecretRef != "") && (n.ClientSecret != "" || n.ClientSecretRef != "")
}

func (t TodoistOAuthConfig) HasClientConfig() bool {
	return (t.ClientID != "" || t.ClientIDSecretRef != "") && (t.ClientSecret != "" || t.ClientSecretRef != "")
}

func (s SlackOAuthConfig) HasClientConfig() bool {
	return (s.ClientID != "" || s.ClientIDSecretRef != "") && (s.ClientSecret != "" || s.ClientSecretRef != "")
}

func (g GitHubOAuthConfig) HasClientConfig() bool {
	return (g.ClientID != "" || g.ClientIDSecretRef != "") && (g.ClientSecret != "" || g.ClientSecretRef != "")
}

func GoogleOAuthConfigForCredential(cfg *Config, credentialID string) (GoogleOAuthConfig, bool) {
	if credentialID == "" || credentialID == cfg.GoogleOAuthCredentialID() {
		if cfg.Server.OAuth.Google.HasClientConfig() {
			return cfg.Server.OAuth.Google, true
		}
		return GoogleOAuthConfig{}, false
	}
	return GoogleOAuthConfig{}, false
}

func NotionOAuthConfigForCredential(cfg *Config, credentialID string) (NotionOAuthConfig, bool) {
	if credentialID == "" || credentialID == cfg.NotionOAuthCredentialID() {
		if cfg.Server.OAuth.Notion.HasClientConfig() {
			return cfg.Server.OAuth.Notion, true
		}
		return NotionOAuthConfig{}, false
	}
	return NotionOAuthConfig{}, false
}

func TodoistOAuthConfigForCredential(cfg *Config, credentialID string) (TodoistOAuthConfig, bool) {
	if credentialID == "" || credentialID == cfg.TodoistOAuthCredentialID() {
		if cfg.Server.OAuth.Todoist.HasClientConfig() {
			return cfg.Server.OAuth.Todoist, true
		}
		return TodoistOAuthConfig{}, false
	}
	return TodoistOAuthConfig{}, false
}

func SlackOAuthConfigForCredential(cfg *Config, credentialID string) (SlackOAuthConfig, bool) {
	if credentialID == "" || credentialID == cfg.SlackOAuthCredentialID() {
		if cfg.Server.OAuth.Slack.HasClientConfig() {
			return cfg.Server.OAuth.Slack, true
		}
		return SlackOAuthConfig{}, false
	}
	return SlackOAuthConfig{}, false
}

func GitHubOAuthConfigForCredential(cfg *Config, credentialID string) (GitHubOAuthConfig, bool) {
	if credentialID == "" || credentialID == cfg.GitHubOAuthCredentialID() {
		if cfg.Server.OAuth.GitHub.HasClientConfig() {
			return cfg.Server.OAuth.GitHub, true
		}
		return GitHubOAuthConfig{}, false
	}
	return GitHubOAuthConfig{}, false
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

func (c *Config) UserSecretNames() map[string]string {
	names := make(map[string]string, len(c.Server.Users))
	for userID, user := range c.Server.Users {
		names[userID] = user.SecretName
	}
	return names
}

func (c *Config) HasUser(userID string) bool {
	if _, ok := c.Server.Users[userID]; ok {
		return true
	}
	return c.Server.Secrets.Mode == "kubernetes" && c.Server.Secrets.Kubernetes.DynamicUsers && ValidDynamicUserID(userID)
}

func (c *Config) HasConfiguredUser(userID string) bool {
	_, ok := c.Server.Users[userID]
	return ok
}

func (c *Config) HasDynamicUser(userID string) bool {
	if c.HasConfiguredUser(userID) {
		return false
	}
	return c.Server.Secrets.Mode == "kubernetes" && c.Server.Secrets.Kubernetes.DynamicUsers && ValidDynamicUserID(userID)
}

func CredentialUserID(cfg *Config, cred CredentialConfig) string {
	if user := cred.Params["user"]; user != "" {
		return user
	}
	if user, _, ok := strings.Cut(cred.ID, "."); ok && cfg.HasUser(user) {
		return user
	}
	return cred.ID
}

func ValidDynamicUserID(userID string) bool {
	if userID == "" || len(userID) > 63 {
		return false
	}
	for i, r := range userID {
		isLower := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		isHyphen := r == '-'
		if !isLower && !isDigit && !isHyphen {
			return false
		}
		if (i == 0 || i == len(userID)-1) && isHyphen {
			return false
		}
	}
	return true
}

func validSecretNamePrefix(prefix string) bool {
	if prefix == "" || len(prefix) >= 253 {
		return false
	}
	for i, r := range prefix {
		isLower := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		isHyphen := r == '-'
		if !isLower && !isDigit && !isHyphen {
			return false
		}
		if i == 0 && isHyphen {
			return false
		}
	}
	return true
}
