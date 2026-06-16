package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/takutakahashi/scia/internal/approval"
	"github.com/takutakahashi/scia/internal/auth"
	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/policy"
)

type Handler struct {
	store     *config.Store
	approval *approval.Manager
	injector  *auth.Injector
	transport *http.Transport
	logger    *slog.Logger
}

func NewHandler(store *config.Store, approvals *approval.Manager, logger *slog.Logger) *Handler {
	return &Handler{
		store:     store,
		approval: approvals,
		injector:  auth.NewInjector(),
		transport: &http.Transport{
			Proxy:                 nil,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
		logger: logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() && strings.HasPrefix(r.URL.Path, "/_scia/") {
		h.serveAdmin(w, r)
		return
	}
	if r.Method == http.MethodConnect {
		h.serveConnect(w, r)
		return
	}
	h.serveForward(w, r)
}

func (h *Handler) serveForward(w http.ResponseWriter, r *http.Request) {
	target, err := config.TargetURL(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := h.store.Get()
	decision := policy.Evaluate(cfg, r, target.Host)
	if !h.authorizeDecision(w, r, decision, target.String()) {
		return
	}

	next := config.CloneRequestWithoutProxyHeaders(r)
	next.URL = target
	if err := h.injector.Apply(r.Context(), next, cfg, decision.Credentials); err != nil {
		h.logger.Error("credential injection failed", "error", err)
		http.Error(w, "credential injection failed", http.StatusBadGateway)
		return
	}

	resp, err := h.transport.RoundTrip(next)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err, "url", target.String())
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *Handler) serveConnect(w http.ResponseWriter, r *http.Request) {
	cfg := h.store.Get()
	decision := policy.Evaluate(cfg, r, r.Host)
	if !h.authorizeDecision(w, r, decision, r.Host) {
		return
	}
	upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "connect failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	errCh := make(chan error, 2)
	go proxyCopy(errCh, upstream, client)
	go proxyCopy(errCh, client, upstream)
	<-errCh
}

func (h *Handler) authorizeDecision(w http.ResponseWriter, r *http.Request, decision policy.Decision, target string) bool {
	switch decision.Action {
	case "deny":
		http.Error(w, "request denied by policy", http.StatusForbidden)
		return false
	case "approval":
		status, err := h.approval.Wait(r.Context(), approval.Request{
			Method: r.Method,
			URL:    target,
			Rule:   decision.Rule.Name,
			Note:   decision.Rule.ApprovalNote,
		})
		if err != nil || status != approval.Approved {
			http.Error(w, "request was not approved", http.StatusForbidden)
			return false
		}
	}
	return true
}

func (h *Handler) serveAdmin(w http.ResponseWriter, r *http.Request) {
	cfg := h.store.Get()
	adminToken := config.HeaderValueFromEnv(cfg.Server.AdminToken)
	if adminToken != "" && r.Header.Get("Authorization") != "Bearer "+adminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/_scia/healthz":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/_scia/approvals":
		writeJSON(w, h.approval.List())
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_scia/approvals/"):
		id, action, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/_scia/approvals/"), "/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		var status approval.Status
		switch action {
		case "approve":
			status = approval.Approved
		case "deny":
			status = approval.Denied
		default:
			http.NotFound(w, r)
			return
		}
		if !h.approval.Resolve(id, status) {
			http.Error(w, "approval request not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func proxyCopy(errCh chan<- error, dst io.Writer, src io.Reader) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
