package secrets

import (
	"context"
	"testing"
)

func TestResolveRefUsesEnv(t *testing.T) {
	t.Setenv("SCIA_TEST_CLIENT_SECRET", "env-secret")

	value, err := ResolveRef(context.Background(), NoopStore{}, "env:SCIA_TEST_CLIENT_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if value != "env-secret" {
		t.Fatalf("unexpected value: %q", value)
	}
}

func TestResolveRefUsesExplicitSecretRef(t *testing.T) {
	store := mapStore{values: map[string]string{"service-a.google:client-secret": "stored-secret"}}

	value, err := ResolveRef(context.Background(), store, "secret:service-a.google.client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if value != "stored-secret" {
		t.Fatalf("unexpected value: %q", value)
	}
}

func TestResolveRefUsesImplicitSecretRef(t *testing.T) {
	store := mapStore{values: map[string]string{"service-a.google:client-secret": "stored-secret"}}

	value, err := ResolveRef(context.Background(), store, "service-a.google.client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if value != "stored-secret" {
		t.Fatalf("unexpected value: %q", value)
	}
}

type mapStore struct {
	values map[string]string
}

func (s mapStore) Get(_ context.Context, credentialID, key string) (string, bool, error) {
	value, ok := s.values[credentialID+":"+key]
	return value, ok, nil
}

func (s mapStore) Put(_ context.Context, credentialID, key, value string) error {
	s.values[credentialID+":"+key] = value
	return nil
}

func (s mapStore) Close() error {
	return nil
}
