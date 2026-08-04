package secrets

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestEnvelopeStoreRoundTripAndCiphertextAtRest(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	store := newTestEnvelopeStore(t, inner, 1)

	if err := store.Put(ctx, "github", "access_token", "secret-token"); err != nil {
		t.Fatal(err)
	}
	stored := inner.values["github\x00access_token"]
	if !strings.HasPrefix(stored, envelopePrefix) {
		t.Fatalf("value was not stored as an envelope: %q", stored)
	}
	if strings.Contains(stored, "secret-token") {
		t.Fatal("stored envelope contains plaintext")
	}

	got, ok, err := store.Get(ctx, "github", "access_token")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != "secret-token" {
		t.Fatalf("unexpected result: got=%q ok=%v", got, ok)
	}
}

func TestEnvelopeStoreUsesRandomDEK(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	store := newTestEnvelopeStore(t, inner, 2)

	if err := store.Put(ctx, "github", "token", "same-value"); err != nil {
		t.Fatal(err)
	}
	first := inner.values["github\x00token"]
	if err := store.Put(ctx, "github", "token", "same-value"); err != nil {
		t.Fatal(err)
	}
	if second := inner.values["github\x00token"]; first == second {
		t.Fatal("two writes produced the same envelope")
	}
}

func TestEnvelopeStoreRejectsPlaintext(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{
		"github\x00token": "legacy-value",
	}}
	store := newTestEnvelopeStore(t, inner, 3)

	if _, _, err := store.Get(ctx, "github", "token"); err == nil {
		t.Fatal("expected plaintext value to fail")
	}
}

func TestEnvelopeStoreRejectsWrongKeyAndMovedCiphertext(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	store := newTestEnvelopeStore(t, inner, 4)
	if err := store.Put(ctx, "github", "token", "secret"); err != nil {
		t.Fatal(err)
	}

	wrongKeyStore := newTestEnvelopeStore(t, inner, 5)
	if _, _, err := wrongKeyStore.Get(ctx, "github", "token"); err == nil {
		t.Fatal("expected the wrong key to fail")
	}

	inner.values["github\x00other"] = inner.values["github\x00token"]
	if _, _, err := store.Get(ctx, "github", "other"); err == nil {
		t.Fatal("expected ciphertext moved to another record to fail")
	}
}

func TestNewEnvelopeStoreValidatesKey(t *testing.T) {
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	for _, key := range []string{"not-base64", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		if _, err := NewEnvelopeStore(inner, key); err == nil {
			t.Fatalf("expected invalid key %q to fail", key)
		}
	}
}

func newTestEnvelopeStore(t *testing.T, inner Store, fill byte) *EnvelopeStore {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	store, err := NewEnvelopeStore(inner, base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type memoryEnvelopeStore struct {
	values map[string]string
}

func (s *memoryEnvelopeStore) Get(_ context.Context, credentialID, key string) (string, bool, error) {
	value, ok := s.values[credentialID+"\x00"+key]
	return value, ok, nil
}

func (s *memoryEnvelopeStore) Put(_ context.Context, credentialID, key, value string) error {
	s.values[credentialID+"\x00"+key] = value
	return nil
}

func (s *memoryEnvelopeStore) Delete(_ context.Context, credentialID, key string) error {
	delete(s.values, credentialID+"\x00"+key)
	return nil
}

func (s *memoryEnvelopeStore) Close() error { return nil }
