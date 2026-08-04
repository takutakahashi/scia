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
		store, err := NewSQLiteStore(ctx, cfg.Server.Secrets.SQLitePath)
		if err != nil {
			return nil, err
		}
		encryptionKey := cfg.Server.Secrets.EnvelopeEncryption.Key
		encryptedStore, err := NewEnvelopeStore(store, encryptionKey)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("sqlite envelope encryption: %w", err)
		}
		return encryptedStore, nil
	case "kubernetes":
		restConfig, err := KubernetesRESTConfig()
		if err != nil {
			return nil, fmt.Errorf("kubernetes client config: %w", err)
		}
		return NewKubernetesStoreFromRESTConfig(restConfig, cfg.Server.Secrets.Kubernetes.Namespace, cfg.UserSecretNames(), KubernetesStoreOptions{
			DynamicUsers:                cfg.Server.Secrets.Kubernetes.DynamicUsers,
			DynamicUserSecretNamePrefix: cfg.Server.Secrets.Kubernetes.DynamicUserSecretNamePrefix,
		})
	case "external":
		webhook := cfg.Server.Secrets.External.Webhook
		return NewExternalStore(config.HeaderValueFromEnv(webhook.URL), config.HeaderValueFromEnv(webhook.SecretKey), nil)
	default:
		return nil, fmt.Errorf("unsupported secrets mode %q", mode)
	}
}
