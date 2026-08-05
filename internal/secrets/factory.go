package secrets

import (
	"context"
	"fmt"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
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
		envelope := cfg.Server.Secrets.EnvelopeEncryption
		if envelope.Provider == "" {
			_ = store.Close()
			return nil, fmt.Errorf("sqlite envelope encryption provider is required")
		}
		cacheTTL := 5 * time.Minute
		if envelope.CacheTTL != nil {
			cacheTTL = envelope.CacheTTL.Duration
		}
		cacheMaxEntries := 1000
		if envelope.CacheMaxEntries != nil {
			cacheMaxEntries = *envelope.CacheMaxEntries
		}
		var kmsClient awsKMSClient
		keyID := envelope.AWSKMS.KeyID
		switch envelope.Provider {
		case "aws-kms":
			if keyID == "" {
				_ = store.Close()
				return nil, fmt.Errorf("sqlite envelope encryption: aws KMS key ID is required")
			}
			loadOptions := []func(*awsconfig.LoadOptions) error{}
			if envelope.AWSKMS.Region != "" {
				loadOptions = append(loadOptions, awsconfig.WithRegion(envelope.AWSKMS.Region))
			}
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
			if err != nil {
				_ = store.Close()
				return nil, fmt.Errorf("sqlite envelope encryption: load AWS config: %w", err)
			}
			kmsClient = kms.NewFromConfig(awsCfg)
		case "kms-broker":
			keyID = kmsBrokerKeyID
			kmsClient, err = NewKMSBrokerClient(
				config.HeaderValueFromEnv(envelope.KMSBroker.URL),
				config.HeaderValueFromEnv(envelope.KMSBroker.Token),
				nil,
			)
			if err != nil {
				_ = store.Close()
				return nil, fmt.Errorf("sqlite envelope encryption: %w", err)
			}
		default:
			_ = store.Close()
			return nil, fmt.Errorf("sqlite envelope encryption: unsupported provider %q", envelope.Provider)
		}
		encryptedStore, err := NewAWSKMSEnvelopeStore(store, kmsClient, AWSKMSEnvelopeOptions{
			KeyID:             keyID,
			EncryptionContext: envelope.EncryptionContext,
			CacheTTL:          cacheTTL,
			CacheMaxEntries:   cacheMaxEntries,
		})
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
