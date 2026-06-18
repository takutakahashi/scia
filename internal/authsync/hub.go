package authsync

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/takutakahashi/scia/internal/config"
)

type Delivery struct {
	Type         string `json:"type"`
	DeliveryID   string `json:"delivery_id"`
	CredentialID string `json:"credential_id"`
	Key          string `json:"key"`
	Value        string `json:"value"`
}

type Hub struct {
	store  *config.Store
	logger *slog.Logger

	mu      sync.Mutex
	client  chan Delivery
	pending []Delivery
}

func NewHub(store *config.Store, logger *slog.Logger) *Hub {
	return &Hub{store: store, logger: logger}
}

func (h *Hub) Enabled() bool {
	return h.store.Get().Server.AuthSync.Mode == "memory"
}

func (h *Hub) Publish(delivery Delivery) bool {
	if !h.Enabled() {
		return false
	}
	if delivery.Type == "" {
		delivery.Type = "token.deliver"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client == nil {
		h.pending = append(h.pending, delivery)
		h.logger.Info("queued auth sync delivery", "credential", delivery.CredentialID, "key", delivery.Key)
		return true
	}
	select {
	case h.client <- delivery:
	default:
		h.pending = append(h.pending, delivery)
		h.logger.Warn("auth sync client queue is full; queued delivery", "credential", delivery.CredentialID, "key", delivery.Key)
	}
	return true
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.Enabled() {
		http.Error(w, "auth sync is disabled", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.authorize(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is unsupported", http.StatusInternalServerError)
		return
	}
	ch := make(chan Delivery, 32)
	h.register(ch)
	defer h.unregister(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case delivery := <-ch:
			body, err := json.Marshal(delivery)
			if err != nil {
				h.logger.Error("failed to encode auth sync delivery", "error", err)
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\n", delivery.Type)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", body)
			flusher.Flush()
		}
	}
}

func (h *Hub) authorize(r *http.Request) error {
	want := config.HeaderValueFromEnv(h.store.Get().Server.AuthSync.Token)
	if want == "" {
		return nil
	}
	if got := bearerToken(r); got != want {
		return fmt.Errorf("invalid auth sync token")
	}
	return nil
}

func (h *Hub) register(ch chan Delivery) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.client = ch
	for _, delivery := range h.pending {
		select {
		case ch <- delivery:
		default:
			return
		}
	}
	h.pending = nil
	h.logger.Info("auth sync proxy connected")
}

func (h *Hub) unregister(ch chan Delivery) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.client == ch {
		h.client = nil
		h.logger.Info("auth sync proxy disconnected")
	}
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return ""
	}
	return value[len(prefix):]
}
