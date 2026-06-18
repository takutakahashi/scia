package secrets

import (
	"context"
	"fmt"

	"github.com/takutakahashi/scia/internal/config"
)

func NewFromConfig(ctx context.Context, cfg *config.Config) (Store, error) {
	mode := cfg.Server.Secrets.Mode
	if mode == "" {
		mode = "sqlite"
	}
	switch mode {
	case "sqlite":
		return NewSQLiteStore(ctx, cfg.Server.Secrets.SQLitePath)
	case "kubernetes":
		restConfig, err := KubernetesRESTConfig()
		if err != nil {
			return nil, fmt.Errorf("kubernetes client config: %w", err)
		}
		return NewKubernetesStoreFromRESTConfig(restConfig, cfg.Server.Secrets.Kubernetes.Namespace, cfg.UserSecretNames())
	default:
		return nil, fmt.Errorf("unsupported secrets mode %q", mode)
	}
}
