package secrets

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/takutakahashi/scia/internal/config"
)

func TestNewFromConfigRequiresAWSKMSKeyID(t *testing.T) {
	_, err := NewFromConfig(context.Background(), &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{Mode: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "secrets.db")},
		},
	})
	if err == nil {
		t.Fatal("expected a missing AWS KMS key ID to fail")
	}
}
