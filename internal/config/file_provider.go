package config

import (
	"context"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type FileProvider struct {
	path   string
	logger *slog.Logger
}

func NewFileProvider(path string, logger *slog.Logger) *FileProvider {
	return &FileProvider{path: path, logger: logger}
}

func (p *FileProvider) Load(context.Context) (*Config, error) {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (p *FileProvider) Watch(ctx context.Context, out chan<- *Config) error {
	var lastMod time.Time
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			info, err := os.Stat(p.path)
			if err != nil {
				p.logger.Error("failed to stat config", "error", err)
				continue
			}
			if !lastMod.IsZero() && !info.ModTime().After(lastMod) {
				continue
			}
			lastMod = info.ModTime()
			cfg, err := p.Load(ctx)
			if err != nil {
				p.logger.Error("failed to reload config", "error", err)
				continue
			}
			select {
			case out <- cfg:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
