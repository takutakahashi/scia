package secrets

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSQLiteStorePutGet(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.Put(ctx, "google", "refresh_token", "refresh-token"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "google", "refresh_token")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected stored secret")
	}
	if got != "refresh-token" {
		t.Fatalf("unexpected secret: %q", got)
	}
}
