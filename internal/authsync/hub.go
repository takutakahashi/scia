package authsync

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	ProxyID      string `json:"proxy_id"`
	CredentialID string `json:"credential_id"`
	Key          string `json:"key"`
	Value        string `json:"value"`
}

type ProxyRegistration struct {
	ProxyID    string   `json:"proxy_id"`
	Token      string   `json:"token,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

type registeredProxy struct {
	tokenHash  [32]byte
	namespaces map[string]struct{}
}

type connection struct {
	proxyID string
	ch      chan Delivery
}

type Hub struct {
	store  *config.Store
	logger *slog.Logger

	mu            sync.Mutex
	connections   map[string]connection
	pending       map[string][]Delivery
	registrations map[string]registeredProxy
}

func NewHub(store *config.Store, logger *slog.Logger) *Hub {
	return &Hub{
		store:         store,
		logger:        logger,
		connections:   map[string]connection{},
		pending:       map[string][]Delivery{},
		registrations: map[string]registeredProxy{},
	}
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
	if delivery.ProxyID == "" {
		h.logger.Error("auth sync delivery is missing proxy_id", "credential", delivery.CredentialID, "key", delivery.Key)
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.allowedLocked(delivery.ProxyID, delivery.CredentialID) {
		h.logger.Error("auth sync delivery is not allowed for proxy", "proxy", delivery.ProxyID, "credential", delivery.CredentialID)
		return false
	}
	conn, ok := h.connections[delivery.ProxyID]
	if !ok {
		h.pending[delivery.ProxyID] = append(h.pending[delivery.ProxyID], delivery)
		h.logger.Info("queued auth sync delivery", "proxy", delivery.ProxyID, "credential", delivery.CredentialID, "key", delivery.Key)
		return true
	}
	select {
	case conn.ch <- delivery:
	default:
		h.pending[delivery.ProxyID] = append(h.pending[delivery.ProxyID], delivery)
		h.logger.Warn("auth sync client queue is full; queued delivery", "proxy", delivery.ProxyID, "credential", delivery.CredentialID, "key", delivery.Key)
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
	proxyID, err := h.authorize(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is unsupported", http.StatusInternalServerError)
		return
	}
	ch := make(chan Delivery, 32)
	if err := h.register(proxyID, ch); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer h.unregister(proxyID, ch)

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

func (h *Hub) ServeRegister(w http.ResponseWriter, r *http.Request) {
	if !h.Enabled() {
		http.Error(w, "auth sync is disabled", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorizeAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req ProxyRegistration
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	if req.ProxyID == "" {
		var err error
		req.ProxyID, err = randomProxyID()
		if err != nil {
			http.Error(w, "failed to create proxy id", http.StatusInternalServerError)
			return
		}
	}
	reg := registeredProxy{tokenHash: sha256.Sum256([]byte(req.Token)), namespaces: map[string]struct{}{}}
	for _, namespace := range req.Namespaces {
		if namespace != "" {
			reg.namespaces[namespace] = struct{}{}
		}
	}
	h.mu.Lock()
	h.registrations[req.ProxyID] = reg
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ProxyRegistration{ProxyID: req.ProxyID, Namespaces: req.Namespaces})
}

func (h *Hub) authorize(r *http.Request) (string, error) {
	proxyID := r.Header.Get("X-Scia-Proxy-ID")
	if proxyID == "" {
		return "", fmt.Errorf("missing proxy id")
	}
	got := bearerToken(r)
	if got == "" {
		return "", fmt.Errorf("missing auth sync token")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	reg, ok := h.registrations[proxyID]
	if !ok {
		return "", fmt.Errorf("unknown proxy id")
	}
	if sha256.Sum256([]byte(got)) != reg.tokenHash {
		return "", fmt.Errorf("invalid auth sync token")
	}
	return proxyID, nil
}

func (h *Hub) authorizeAdmin(r *http.Request) bool {
	want := config.HeaderValueFromEnv(h.store.Get().Server.AdminToken)
	return want != "" && bearerToken(r) == want
}

func (h *Hub) register(proxyID string, ch chan Delivery) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.connections[proxyID]; ok {
		return fmt.Errorf("proxy is already connected")
	}
	h.connections[proxyID] = connection{proxyID: proxyID, ch: ch}
	for _, delivery := range h.pending[proxyID] {
		select {
		case ch <- delivery:
		default:
			return nil
		}
	}
	delete(h.pending, proxyID)
	h.logger.Info("auth sync proxy connected", "proxy", proxyID)
	return nil
}

func (h *Hub) unregister(proxyID string, ch chan Delivery) {
	h.mu.Lock()
	defer h.mu.Unlock()
	conn, ok := h.connections[proxyID]
	if ok && conn.ch == ch {
		delete(h.connections, proxyID)
		h.logger.Info("auth sync proxy disconnected", "proxy", proxyID)
	}
}

func (h *Hub) allowedLocked(proxyID, credentialID string) bool {
	reg, ok := h.registrations[proxyID]
	if !ok {
		return false
	}
	if len(reg.namespaces) == 0 {
		return true
	}
	namespace, ok := config.GoogleCredentialNamespace(credentialID)
	if !ok {
		return false
	}
	_, ok = reg.namespaces[namespace]
	return ok
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return ""
	}
	return value[len(prefix):]
}

func randomProxyID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "proxy_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}
