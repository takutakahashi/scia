package authsync

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
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
				ProxyID: "proxy-a",
			},
			AdminToken: "admin-token",
		},
	})
	hub := NewHub(store, slog.Default())
	server := newAuthSyncTestServer(hub)
	defer server.Close()
	registerProxy(t, server, "proxy-a", "sync-token", []string{"service-a"})

	secretStore := newMemoryStore()
	proxyStore := newTestConfigStore(t, &config.Config{
		Server: config.ServerConfig{
			AuthSync: config.AuthSyncConfig{
				URL:     server.URL + "/_scia/auth-sync/events",
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
		_, ok := hub.connections["proxy-a"]
		return ok
	})
	hub.Publish(Delivery{
		Type:         "token.deliver",
		DeliveryID:   "delivery-1",
		ProxyID:      "proxy-a",
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
				Mode: "memory",
			},
			AdminToken: "admin-token",
		},
	})
	hub := NewHub(store, slog.Default())
	server := newAuthSyncTestServer(hub)
	defer server.Close()
	registerProxy(t, server, "proxy-a", "sync-token", nil)

	resp, err := server.Client().Get(server.URL + "/_scia/auth-sync/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func TestHubRoutesDeliveryByProxyID(t *testing.T) {
	store := newTestConfigStore(t, &config.Config{
		Server: config.ServerConfig{
			AuthSync:   config.AuthSyncConfig{Mode: "memory"},
			AdminToken: "admin-token",
		},
	})
	hub := NewHub(store, slog.Default())
	server := newAuthSyncTestServer(hub)
	defer server.Close()
	registerProxy(t, server, "proxy-a", "token-a", []string{"service-a"})
	registerProxy(t, server, "proxy-b", "token-b", []string{"service-a"})

	secretA := newMemoryStore()
	secretB := newMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewClient(newTestConfigStore(t, &config.Config{Server: config.ServerConfig{AuthSync: config.AuthSyncConfig{URL: server.URL + "/_scia/auth-sync/events", ProxyID: "proxy-a", Token: "token-a"}}}), secretA, slog.Default()).connect(ctx)
	}()
	go func() {
		_ = NewClient(newTestConfigStore(t, &config.Config{Server: config.ServerConfig{AuthSync: config.AuthSyncConfig{URL: server.URL + "/_scia/auth-sync/events", ProxyID: "proxy-b", Token: "token-b"}}}), secretB, slog.Default()).connect(ctx)
	}()
	waitUntil(t, func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.connections) == 2
	})

	hub.Publish(Delivery{Type: "token.deliver", DeliveryID: "delivery-1", ProxyID: "proxy-b", CredentialID: "service-a.google", Key: "refresh_token", Value: "token-b"})

	waitUntil(t, func() bool {
		value, ok, err := secretB.Get(context.Background(), "service-a.google", "refresh_token")
		return err == nil && ok && value == "token-b"
	})
	if value, ok, err := secretA.Get(context.Background(), "service-a.google", "refresh_token"); err != nil || ok || value != "" {
		t.Fatalf("delivery leaked to proxy-a: value=%q ok=%v err=%v", value, ok, err)
	}
}

func registerProxy(t *testing.T, server *httptest.Server, proxyID, token string, namespaces []string) {
	t.Helper()
	body, err := json.Marshal(ProxyRegistration{ProxyID: proxyID, Token: token, Namespaces: namespaces})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/_scia/auth-sync/proxies", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected register status: %d", resp.StatusCode)
	}
}

func newAuthSyncTestServer(hub *Hub) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/_scia/auth-sync/events", hub)
	mux.HandleFunc("/_scia/auth-sync/proxies", hub.ServeRegister)
	return httptest.NewServer(mux)
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
