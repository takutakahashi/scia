package authsync

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/takutakahashi/scia/internal/config"
)

type staticProvider struct {
	cfg *config.Config
}

func (p staticProvider) Load(context.Context) (*config.Config, error) {
	return p.cfg, nil
}

func (p staticProvider) Watch(ctx context.Context, out chan<- *config.Config) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestClientStoresDeliveryFromHub(t *testing.T) {
	store := newTestConfigStore(t, &config.Config{
		Server: config.ServerConfig{
			AuthSync: config.AuthSyncConfig{
				Mode:    "memory",
				Token:   "sync-token",
				ProxyID: "proxy-a",
			},
		},
	})
	hub := NewHub(store, slog.Default())
	server := httptest.NewServer(hub)
	defer server.Close()

	secretStore := newMemoryStore()
	proxyStore := newTestConfigStore(t, &config.Config{
		Server: config.ServerConfig{
			AuthSync: config.AuthSyncConfig{
				URL:     server.URL,
				Token:   "sync-token",
				ProxyID: "proxy-a",
			},
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- NewClient(proxyStore, secretStore, slog.Default()).connect(ctx)
	}()

	waitUntil(t, func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return hub.client != nil
	})
	hub.Publish(Delivery{
		Type:         "token.deliver",
		DeliveryID:   "delivery-1",
		CredentialID: "service-a.google",
		Key:          "refresh_token",
		Value:        "refresh-token",
	})

	waitUntil(t, func() bool {
		value, ok, err := secretStore.Get(context.Background(), "service-a.google", "refresh_token")
		return err == nil && ok && value == "refresh-token"
	})
	cancel()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("auth sync client did not stop")
	}
}

func TestHubRequiresBearerToken(t *testing.T) {
	store := newTestConfigStore(t, &config.Config{
		Server: config.ServerConfig{
			AuthSync: config.AuthSyncConfig{
				Mode:  "memory",
				Token: "sync-token",
			},
		},
	})
	server := httptest.NewServer(NewHub(store, slog.Default()))
	defer server.Close()

	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func newTestConfigStore(t *testing.T, cfg *config.Config) *config.Store {
	t.Helper()
	store, err := config.NewStore(context.Background(), staticProvider{cfg: cfg}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func waitUntil(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied")
}

type memoryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{values: map[string]string{}}
}

func (s *memoryStore) Get(_ context.Context, credentialID, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[credentialID+":"+key]
	return value, ok, nil
}

func (s *memoryStore) Put(_ context.Context, credentialID, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[credentialID+":"+key] = value
	return nil
}

func (s *memoryStore) Close() error {
	return nil
}
