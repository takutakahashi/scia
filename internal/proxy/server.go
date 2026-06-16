package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/takutakahashi/scia/internal/approval"
	"github.com/takutakahashi/scia/internal/auth"
	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/policy"
	"github.com/takutakahashi/scia/internal/secrets"
)

type Handler struct {
	store      *config.Store
	approval   *approval.Manager
	injector   *auth.Injector
	transport  *http.Transport
	logger     *slog.Logger
	caMu       sync.RWMutex
	ca         *certificateAuthority
	caCertPath string
	caKeyPath  string
}

func NewHandler(store *config.Store, secretStore secrets.Store, approvals *approval.Manager, logger *slog.Logger) (*Handler, error) {
	cfg := store.Get()
	ca, err := loadOrCreateCA(cfg.Server.MITM.CACertPath, cfg.Server.MITM.CAKeyPath)
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		store:    store,
		approval: approvals,
		injector: auth.NewInjector(secretStore),
		transport: &http.Transport{
			Proxy:                 nil,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
		logger:     logger,
		ca:         ca,
		caCertPath: cfg.Server.MITM.CACertPath,
		caKeyPath:  cfg.Server.MITM.CAKeyPath,
	}
	handler.transport.Proxy = handler.backendProxy
	return handler, nil
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
	h.serveMITMConnect(w, r)
}

func (h *Handler) serveMITMConnect(w http.ResponseWriter, r *http.Request) {
	cfg := h.store.Get()
	ca, err := h.currentCA(cfg)
	if err != nil {
		h.logger.Error("failed to load mitm ca", "error", err)
		http.Error(w, "mitm ca is not initialized", http.StatusBadGateway)
		return
	}
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

	host := stripPort(r.Host)
	cert, err := ca.certForHost(host)
	if err != nil {
		_ = client.Close()
		h.logger.Error("failed to generate leaf certificate", "error", err, "host", host)
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		return
	}

	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		h.logger.Debug("mitm tls handshake failed", "error", err, "host", r.Host)
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)
	for {
		inner, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				h.logger.Debug("mitm request read failed", "error", err, "host", r.Host)
			}
			return
		}
		resp := h.roundTripMITMRequest(inner, r.Host)
		if err := resp.Write(tlsConn); err != nil {
			_ = inner.Body.Close()
			_ = resp.Body.Close()
			h.logger.Debug("mitm response write failed", "error", err, "host", r.Host)
			return
		}
		_ = inner.Body.Close()
		_ = resp.Body.Close()
		if inner.Close || resp.Close {
			return
		}
	}
}

func (h *Handler) roundTripMITMRequest(r *http.Request, connectHost string) *http.Response {
	cfg := h.store.Get()
	target := &url.URL{
		Scheme:   "https",
		Host:     connectHost,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	decision := policy.Evaluate(cfg, r, connectHost)
	if denial := h.denialResponse(r, decision, target.String()); denial != nil {
		return denial
	}

	next := config.CloneRequestWithoutProxyHeaders(r)
	next.URL = target
	next.Host = connectHost
	if err := h.injector.Apply(r.Context(), next, cfg, decision.Credentials); err != nil {
		h.logger.Error("credential injection failed", "error", err)
		return textResponse(r, http.StatusBadGateway, "credential injection failed\n")
	}

	resp, err := h.transport.RoundTrip(next)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err, "url", target.String())
		return textResponse(r, http.StatusBadGateway, "upstream request failed\n")
	}
	return resp
}

func (h *Handler) authorizeDecision(w http.ResponseWriter, r *http.Request, decision policy.Decision, target string) bool {
	if resp := h.denialResponse(r, decision, target); resp != nil {
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		_ = resp.Body.Close()
		return false
	}
	return true
}

func (h *Handler) denialResponse(r *http.Request, decision policy.Decision, target string) *http.Response {
	switch decision.Action {
	case "deny":
		return textResponse(r, http.StatusForbidden, "request denied by policy\n")
	case "approval":
		status, err := h.approval.Wait(r.Context(), approval.Request{
			Method: r.Method,
			URL:    target,
			Rule:   decision.Rule.Name,
			Note:   decision.Rule.ApprovalNote,
		})
		if err != nil || status != approval.Approved {
			return textResponse(r, http.StatusForbidden, "request was not approved\n")
		}
	}
	return nil
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
	case r.Method == http.MethodGet && r.URL.Path == "/_scia/ca.pem":
		ca, err := h.currentCA(cfg)
		if err != nil {
			h.logger.Error("failed to load mitm ca", "error", err)
			http.Error(w, "mitm ca is not initialized", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(ca.certPEM)
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

func (h *Handler) currentCA(cfg *config.Config) (*certificateAuthority, error) {
	h.caMu.RLock()
	if h.ca != nil && h.caCertPath == cfg.Server.MITM.CACertPath && h.caKeyPath == cfg.Server.MITM.CAKeyPath {
		ca := h.ca
		h.caMu.RUnlock()
		return ca, nil
	}
	h.caMu.RUnlock()

	h.caMu.Lock()
	defer h.caMu.Unlock()
	if h.ca != nil && h.caCertPath == cfg.Server.MITM.CACertPath && h.caKeyPath == cfg.Server.MITM.CAKeyPath {
		return h.ca, nil
	}
	ca, err := loadOrCreateCA(cfg.Server.MITM.CACertPath, cfg.Server.MITM.CAKeyPath)
	if err != nil {
		return nil, err
	}
	h.ca = ca
	h.caCertPath = cfg.Server.MITM.CACertPath
	h.caKeyPath = cfg.Server.MITM.CAKeyPath
	return ca, nil
}

func (h *Handler) backendProxy(r *http.Request) (*url.URL, error) {
	raw := config.HeaderValueFromEnv(h.store.Get().Server.BackendProxy.URL)
	if raw == "" {
		return nil, nil
	}
	return url.Parse(raw)
}

func stripPort(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		return hostname
	}
	return host
}

func textResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       r,
	}
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
