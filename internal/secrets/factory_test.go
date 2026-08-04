package secrets

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/takutakahashi/scia/internal/config"
)

func TestNewFromConfigRequiresSQLiteEnvelopeKey(t *testing.T) {
	_, err := NewFromConfig(context.Background(), &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{Mode: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "secrets.db")},
		},
	})
	if err == nil {
		t.Fatal("expected a missing envelope encryption key to fail")
	}
}

func TestNewFromConfigEncryptsSQLiteValues(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "secrets.db")
	store, err := NewFromConfig(ctx, &config.Config{
		Server: config.ServerConfig{
			Secrets: config.SecretsConfig{
				Mode:       "sqlite",
				SQLitePath: path,
				EnvelopeEncryption: config.EnvelopeEncryptionConfig{
					Key: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.Put(ctx, "github", "token", "secret-token"); err != nil {
		t.Fatal(err)
	}
	inner := store.(*EnvelopeStore).store.(*SQLiteStore)
	var stored string
	if err := inner.db.QueryRowContext(ctx, `SELECT value FROM secrets WHERE credential_id = ? AND key = ?`, "github", "token").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "secret-token" {
		t.Fatal("factory stored plaintext in SQLite")
	}
}
