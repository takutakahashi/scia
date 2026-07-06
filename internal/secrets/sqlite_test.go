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

func TestSQLiteStoreConfiguresLockHandling(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if got := store.db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("unexpected max open connections: %d", got)
	}

	var busyTimeout int
	if err := store.db.QueryRowContext(ctx, `PRAGMA busy_timeout;`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("unexpected busy timeout: %d", busyTimeout)
	}

	var journalMode string
	if err := store.db.QueryRowContext(ctx, `PRAGMA journal_mode;`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("unexpected journal mode: %q", journalMode)
	}
}
