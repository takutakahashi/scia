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
	Listen           string        `yaml:"listen"`
	AdminToken       string        `yaml:"adminToken"`
	ApprovalTimeout Duration      `yaml:"approvalTimeout"`
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
		case "bearer", "basic", "static-header", "oauth2-client-credentials":
		default:
			return fmt.Errorf("credential %q has unsupported type %q", cred.ID, cred.Type)
		}
		if cred.Type == "static-header" && cred.Header == "" {
			return fmt.Errorf("credential %q requires header", cred.ID)
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
	return CredentialConfig{}, false
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
