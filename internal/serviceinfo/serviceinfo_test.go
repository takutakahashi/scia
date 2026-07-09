package serviceinfo

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/takutakahashi/scia/internal/config"
)

func TestPutDoesNotStoreOAuthClientValues(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()

	err := Put(ctx, store, "example", config.ServiceConfig{
		Hosts: []config.ServiceHostRule{{Host: "api.example.com"}},
		OAuth: &config.ServiceOAuthConfig{
			CredentialID:      "example",
			ClientID:          "client-id",
			ClientIDSecretRef: "env:EXAMPLE_CLIENT_ID",
			ClientSecret:      "client-secret",
			ClientSecretRef:   "env:EXAMPLE_CLIENT_SECRET",
			AuthURL:           "https://auth.example.com/oauth/authorize",
			TokenURL:          "https://auth.example.com/oauth/token",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, ok, err := store.Get(ctx, "example", SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected stored service metadata")
	}
	if strings.Contains(raw, "client-id") || strings.Contains(raw, "client-secret") || strings.Contains(raw, "EXAMPLE_CLIENT") {
		t.Fatalf("stored service metadata includes oauth client values or refs: %s", raw)
	}

	var stored storedService
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Service.OAuth == nil {
		t.Fatal("expected stored oauth metadata")
	}
	if stored.Service.OAuth.ClientID != "" || stored.Service.OAuth.ClientIDSecretRef != "" || stored.Service.OAuth.ClientSecret != "" || stored.Service.OAuth.ClientSecretRef != "" {
		t.Fatalf("unexpected stored oauth client values: %#v", stored.Service.OAuth)
	}
}

type memoryStore struct {
	values map[string]string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{values: map[string]string{}}
}

func (s *memoryStore) Get(_ context.Context, credentialID, key string) (string, bool, error) {
	value, ok := s.values[credentialID+"\x00"+key]
	return value, ok, nil
}

func (s *memoryStore) Put(_ context.Context, credentialID, key, value string) error {
	s.values[credentialID+"\x00"+key] = value
	return nil
}

func (s *memoryStore) Delete(_ context.Context, credentialID, key string) error {
	delete(s.values, credentialID+"\x00"+key)
	return nil
}

func (s *memoryStore) Close() error {
	return nil
}
