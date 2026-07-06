package secrets

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.init(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return store, nil
}

func (s *SQLiteStore) configure(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000;`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA journal_mode = WAL;`); err != nil {
		return err
	}
	return nil
}

func (s *SQLiteStore) init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS secrets (
  credential_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (credential_id, key)
);
`)
	return err
}

func (s *SQLiteStore) Get(ctx context.Context, credentialID, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM secrets WHERE credential_id = ? AND key = ?`, credentialID, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (s *SQLiteStore) Put(ctx context.Context, credentialID, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO secrets (credential_id, key, value, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(credential_id, key) DO UPDATE SET
  value = excluded.value,
  updated_at = excluded.updated_at;
`, credentialID, key, value, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *SQLiteStore) Delete(ctx context.Context, credentialID, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE credential_id = ? AND key = ?`, credentialID, key)
	return err
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
