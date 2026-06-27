package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type FileProvider struct {
	paths  []string
	logger *slog.Logger
}

func NewFileProvider(path string, logger *slog.Logger) *FileProvider {
	return NewFileProviderPaths([]string{path}, logger)
}

func NewFileProviderPaths(paths []string, logger *slog.Logger) *FileProvider {
	return &FileProvider{paths: paths, logger: logger}
}

func (p *FileProvider) Load(context.Context) (*Config, error) {
	if len(p.paths) == 0 {
		return nil, fmt.Errorf("at least one config path is required")
	}
	var merged *yaml.Node
	for _, path := range p.paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		root := documentRoot(&doc)
		if merged == nil {
			merged = root
			continue
		}
		merged = mergeYAMLNodes(merged, root)
	}
	var cfg Config
	out := yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{merged}}
	if err := out.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (p *FileProvider) Watch(ctx context.Context, out chan<- *Config) error {
	lastMod := map[string]time.Time{}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			changed := false
			for _, path := range p.paths {
				info, err := os.Stat(path)
				if err != nil {
					p.logger.Error("failed to stat config", "path", path, "error", err)
					continue
				}
				if last, ok := lastMod[path]; !ok || info.ModTime().After(last) {
					lastMod[path] = info.ModTime()
					changed = true
				}
			}
			if !changed {
				continue
			}
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

func documentRoot(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

func mergeYAMLNodes(base, override *yaml.Node) *yaml.Node {
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}
	if base.Kind != yaml.MappingNode || override.Kind != yaml.MappingNode {
		return override
	}
	out := *base
	out.Content = append([]*yaml.Node(nil), base.Content...)
	for i := 0; i+1 < len(override.Content); i += 2 {
		key := override.Content[i]
		value := override.Content[i+1]
		if idx := mappingValueIndex(&out, key.Value); idx >= 0 {
			out.Content[idx] = mergeYAMLNodes(out.Content[idx], value)
			continue
		}
		out.Content = append(out.Content, key, value)
	}
	return &out
}

func mappingValueIndex(node *yaml.Node, key string) int {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return i + 1
		}
	}
	return -1
}
