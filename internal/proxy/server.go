package proxy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/takutakahashi/scia/internal/approval"
	"github.com/takutakahashi/scia/internal/auth"
	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/policy"
	"github.com/takutakahashi/scia/internal/secrets"
	"github.com/takutakahashi/scia/internal/serviceinfo"
)

type Handler struct {
	store      *config.Store
	secrets    secrets.Store
	approval   *approval.Manager
	injector   *auth.Injector
	transport  *http.Transport
	client     *http.Client
	logger     *slog.Logger
	caMu       sync.RWMutex
	ca         *certificateAuthority
	caCertPath string
	caKeyPath  string
}

func NewHandler(store *config.Store, secretStore secrets.Store, approvals *approval.Manager, logger *slog.Logger) (*Handler, error) {
	if secretStore == nil {
		secretStore = secrets.NoopStore{}
	}
	cfg := store.Get()
	ca, err := loadOrCreateCA(cfg.Server.MITM.CACertPath, cfg.Server.MITM.CAKeyPath)
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		store:    store,
		secrets:  secretStore,
		approval: approvals,
		injector: auth.NewInjector(secretStore),
		client:   &http.Client{Timeout: 10 * time.Second},
		transport: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     false,
			TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
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
	if isProxySelfTarget(cfg.Server.Listen, target.Host, target.Scheme) {
		http.Error(w, "proxy self-target denied", http.StatusLoopDetected)
		return
	}
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
	if err := h.injector.ApplyServices(r.Context(), next, cfg, decision.Services); err != nil {
		h.logger.Error("service injection failed", "error", err)
		http.Error(w, "service injection failed", http.StatusBadGateway)
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
	if isProxySelfTarget(cfg.Server.Listen, r.Host, "") {
		http.Error(w, "proxy self-target denied", http.StatusLoopDetected)
		return
	}
	decision := policy.Evaluate(cfg, r, r.Host)
	if !h.authorizeDecision(w, r, decision, r.Host) {
		return
	}
	if len(decision.Services) == 0 && !mitmHostAllowed(integrationMITMHosts(cfg), r.Host) {
		h.serveTunnelConnect(w, r)
		return
	}
	h.serveMITMConnect(w, r)
}

func (h *Handler) serveTunnelConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	upstream, upstreamReader, err := h.dialRawTunnelUpstream(r.Context(), r.Host)
	if err != nil {
		_ = client.Close()
		h.logger.Error("tunnel upstream failed", "error", err, "host", r.Host)
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	_ = pipeBidirectional(client, rw.Reader, upstream, upstreamReader)
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
		ctx := context.WithValue(inner.Context(), mitmClientConnKey{}, tlsConn)
		ctx = context.WithValue(ctx, mitmClientReaderKey{}, reader)
		inner = inner.WithContext(ctx)
		resp := h.roundTripMITMRequest(inner, r.Host)
		if resp == nil {
			_ = inner.Body.Close()
			return
		}
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

	if isWebSocketUpgrade(r) {
		if err := h.handleMITMWebSocket(r, connectHost, cfg, decision); err != nil {
			h.logger.Error("websocket upstream failed", "error", err, "url", target.String())
			return textResponse(r, http.StatusBadGateway, "websocket upstream failed\n")
		}
		return nil
	}

	next := config.CloneRequestWithoutProxyHeaders(r)
	next.URL = target
	next.Host = connectHost
	if err := h.injector.Apply(r.Context(), next, cfg, decision.Credentials); err != nil {
		h.logger.Error("credential injection failed", "error", err)
		return textResponse(r, http.StatusBadGateway, "credential injection failed\n")
	}
	if err := h.injector.ApplyServices(r.Context(), next, cfg, decision.Services); err != nil {
		h.logger.Error("service injection failed", "error", err)
		return textResponse(r, http.StatusBadGateway, "service injection failed\n")
	}

	resp, err := h.transport.RoundTrip(next)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err, "url", target.String())
		return textResponse(r, http.StatusBadGateway, "upstream request failed\n")
	}
	return resp
}

func (h *Handler) handleMITMWebSocket(r *http.Request, connectHost string, cfg *config.Config, decision policy.Decision) error {
	clientConn, ok := r.Context().Value(mitmClientConnKey{}).(net.Conn)
	if !ok {
		return errors.New("missing mitm client connection")
	}
	clientReader, ok := r.Context().Value(mitmClientReaderKey{}).(*bufio.Reader)
	if !ok {
		return errors.New("missing mitm client reader")
	}
	next := cloneWebSocketRequest(r)
	next.URL = &url.URL{Scheme: "https", Host: connectHost, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	next.Host = connectHost
	if err := h.injector.Apply(r.Context(), next, cfg, decision.Credentials); err != nil {
		return fmt.Errorf("credential injection failed: %w", err)
	}
	if err := h.injector.ApplyServices(r.Context(), next, cfg, decision.Services); err != nil {
		return fmt.Errorf("service injection failed: %w", err)
	}

	upstream, err := h.dialWebSocketUpstream(r, connectHost)
	if err != nil {
		return err
	}
	defer upstream.Close()

	if err := writeWebSocketRequest(upstream, next); err != nil {
		return err
	}
	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, next)
	if err != nil {
		return fmt.Errorf("read upstream websocket response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Write(clientConn)
		return nil
	}
	normalizeWebSocketUpgradeResponse(resp, r)
	if err := writeWebSocketResponse(clientConn, resp); err != nil {
		return fmt.Errorf("write websocket response to client: %w", err)
	}
	return pipeBidirectional(clientConn, clientReader, upstream, upstreamReader)
}

type mitmClientConnKey struct{}
type mitmClientReaderKey struct{}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func normalizeWebSocketUpgradeResponse(resp *http.Response, clientReq *http.Request) {
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	resp.Header.Set("Connection", "Upgrade")
	resp.Header.Set("Upgrade", "websocket")
	if key := strings.TrimSpace(clientReq.Header.Get("Sec-WebSocket-Key")); key != "" {
		resp.Header.Set("Sec-WebSocket-Accept", websocketAccept(key))
	}
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func cloneWebSocketRequest(r *http.Request) *http.Request {
	next := r.Clone(r.Context())
	next.RequestURI = ""
	next.Header = r.Header.Clone()
	for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "Keep-Alive"} {
		next.Header.Del(name)
	}
	return next
}

func (h *Handler) dialWebSocketUpstream(r *http.Request, connectHost string) (net.Conn, error) {
	var tcp net.Conn
	var err error
	upstreamReader := (*bufio.Reader)(nil)
	tcp, upstreamReader, err = h.dialRawTunnelUpstream(r.Context(), connectHost)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{}
	if h.transport != nil && h.transport.TLSClientConfig != nil {
		tlsConfig = h.transport.TLSClientConfig.Clone()
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = stripPort(connectHost)
	}
	tlsConfig.NextProtos = []string{"http/1.1"}

	tlsConn := tls.Client(&bufferedConn{Conn: tcp, reader: upstreamReader}, tlsConfig)
	if err := tlsConn.HandshakeContext(r.Context()); err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("upstream tls handshake: %w", err)
	}
	return tlsConn, nil
}

func (h *Handler) dialRawTunnelUpstream(ctx context.Context, connectHost string) (net.Conn, *bufio.Reader, error) {
	rawProxy := config.HeaderValueFromEnv(h.store.Get().Server.BackendProxy.URL)
	if rawProxy == "" {
		conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", connectHost)
		if err != nil {
			return nil, nil, err
		}
		return conn, bufio.NewReader(conn), nil
	}
	return h.dialBackendProxyTunnel(ctx, rawProxy, connectHost)
}

func (h *Handler) dialBackendProxyTunnel(ctx context.Context, rawProxy, connectHost string) (net.Conn, *bufio.Reader, error) {
	proxyURL, err := url.Parse(rawProxy)
	if err != nil {
		return nil, nil, fmt.Errorf("parse backend proxy url: %w", err)
	}
	proxyAddr := proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		if proxyURL.Scheme == "https" {
			proxyAddr += ":443"
		} else {
			proxyAddr += ":80"
		}
	}
	tcp, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial backend proxy: %w", err)
	}
	var conn net.Conn = tcp
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(tcp, &tls.Config{ServerName: stripPort(proxyURL.Host)})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = tcp.Close()
			return nil, nil, fmt.Errorf("backend proxy tls handshake: %w", err)
		}
		conn = tlsConn
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectHost, connectHost); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("write backend proxy connect: %w", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("read backend proxy connect response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("backend proxy connect failed: %s", resp.Status)
	}
	return conn, reader, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func mitmHostAllowed(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	normalized := strings.ToLower(host)
	hostOnly := normalized
	if splitHost, _, err := net.SplitHostPort(normalized); err == nil {
		hostOnly = splitHost
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(pattern)
		if matched, err := path.Match(pattern, normalized); err == nil && matched {
			return true
		}
		if matched, err := path.Match(pattern, hostOnly); err == nil && matched {
			return true
		}
		if pattern == normalized || pattern == hostOnly {
			return true
		}
	}
	return false
}

func integrationMITMHosts(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	hosts := make([]string, 0,
		len(cfg.Server.Integrations.Google.Hosts)+
			len(cfg.Server.Integrations.Notion.Hosts)+
			len(cfg.Server.Integrations.Todoist.Hosts),
	)
	hosts = append(hosts, cfg.Server.Integrations.Google.Hosts...)
	hosts = append(hosts, cfg.Server.Integrations.Notion.Hosts...)
	hosts = append(hosts, cfg.Server.Integrations.Todoist.Hosts...)
	for _, service := range cfg.Server.Services {
		for _, rule := range service.Hosts {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
			if rule.HostSuffix != "" {
				hosts = append(hosts, "*"+rule.HostSuffix)
			}
		}
	}
	return hosts
}

func isProxySelfTarget(listenAddr, targetHost, scheme string) bool {
	listenPort := portFromHost(defaultListenAddr(listenAddr), "")
	if listenPort == "" {
		return false
	}
	targetPort := portFromHost(targetHost, scheme)
	if targetPort != listenPort {
		return false
	}
	host := strings.ToLower(stripPort(targetHost))
	return host == "" ||
		host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1" ||
		host == "::" ||
		host == "0.0.0.0" ||
		host == "[::]"
}

func defaultListenAddr(listenAddr string) string {
	if strings.TrimSpace(listenAddr) == "" {
		return ":8080"
	}
	return listenAddr
}

func portFromHost(host, scheme string) string {
	if _, port, err := net.SplitHostPort(host); err == nil {
		return port
	}
	if strings.HasPrefix(host, ":") {
		return strings.TrimPrefix(host, ":")
	}
	if strings.Contains(host, ":") {
		return ""
	}
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func writeWebSocketRequest(conn net.Conn, r *http.Request) error {
	path := r.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	writer := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(writer, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, path, r.Host); err != nil {
		return fmt.Errorf("write websocket request line: %w", err)
	}
	if err := r.Header.WriteSubset(writer, map[string]bool{"Host": true}); err != nil {
		return fmt.Errorf("write websocket headers: %w", err)
	}
	if _, err := writer.WriteString("\r\n"); err != nil {
		return fmt.Errorf("finish websocket headers: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush websocket request: %w", err)
	}
	return nil
}

func writeWebSocketResponse(conn net.Conn, resp *http.Response) error {
	writer := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)); err != nil {
		return fmt.Errorf("write websocket response status: %w", err)
	}
	if err := resp.Header.Write(writer); err != nil {
		return fmt.Errorf("write websocket response headers: %w", err)
	}
	if _, err := writer.WriteString("\r\n"); err != nil {
		return fmt.Errorf("finish websocket response headers: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush websocket response: %w", err)
	}
	return nil
}

func pipeBidirectional(client net.Conn, clientReader *bufio.Reader, upstream net.Conn, upstreamReader *bufio.Reader) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, clientReader)
		closeWrite(upstream)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(client, upstreamReader)
		closeWrite(client)
		errCh <- err
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		err := <-errCh
		if firstErr == nil && err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			firstErr = err
		}
	}
	_ = client.Close()
	_ = upstream.Close()
	return firstErr
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
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
	case r.Method == http.MethodGet && r.URL.Path == "/_scia/credentials/status":
		h.serveAdminCredentialStatus(w, r)
	case r.Method == http.MethodPost && (r.URL.Path == "/_scia/tokens" || r.URL.Path == "/_scia/secrets"):
		h.serveAdminPutToken(w, r)
	case r.Method == http.MethodPost && (r.URL.Path == "/_scia/tokens/revoke" || r.URL.Path == "/_scia/secrets/revoke"):
		h.serveAdminRevokeToken(w, r)
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

func (h *Handler) serveAdminCredentialStatus(w http.ResponseWriter, r *http.Request) {
	cfg := h.store.Get()
	statuses := make([]adminCredentialStatus, 0)
	for _, cred := range adminStatusCredentials(cfg) {
		storageID := config.CredentialUserID(cfg, cred)
		found, err := h.adminCredentialStoredToken(r.Context(), cfg, cred, storageID)
		if err != nil {
			h.logger.Error("failed to read credential status", "error", err, "credential_id", cred.ID)
			http.Error(w, "failed to read credential status", http.StatusBadGateway)
			return
		}
		statuses = append(statuses, adminCredentialStatus{
			CredentialID:  cred.ID,
			Authenticated: found,
		})
	}
	writeJSON(w, adminCredentialStatusResponse{Credentials: statuses})
}

func adminStatusCredentials(cfg *config.Config) []config.CredentialConfig {
	credentials := make([]config.CredentialConfig, 0, len(cfg.Credentials)+len(cfg.Server.Services))
	seen := map[string]struct{}{}
	for _, cred := range cfg.Credentials {
		if cred.ID == "" {
			continue
		}
		credentials = append(credentials, cred)
		seen[cred.ID] = struct{}{}
	}
	for _, service := range cfg.Server.Services {
		if service.OAuth == nil || service.OAuth.CredentialID == "" {
			continue
		}
		if _, ok := seen[service.OAuth.CredentialID]; ok {
			continue
		}
		credentials = append(credentials, config.CredentialConfig{
			ID:     service.OAuth.CredentialID,
			Type:   "service-oauth",
			Params: map[string]string{},
		})
		seen[service.OAuth.CredentialID] = struct{}{}
	}
	return credentials
}

func (h *Handler) adminCredentialStoredToken(ctx context.Context, cfg *config.Config, cred config.CredentialConfig, storageID string) (bool, error) {
	keys := []string{"refresh_token", "access_token"}
	for _, key := range keys {
		storageKey := adminTokenStorageKey(cfg, storageID, cred.ID, key)
		_, ok, err := h.secrets.Get(ctx, storageID, storageKey)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
		if storageKey != key && key == "refresh_token" && strings.HasSuffix(cred.ID, ".google") {
			_, ok, err := h.secrets.Get(ctx, storageID, key)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
	}
	return false, nil
}

func (h *Handler) serveAdminPutToken(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAdminTokenRequest(w, r)
	if !ok {
		return
	}
	value := req.value()
	if req.CredentialID == "" || req.Key == "" || value == "" {
		http.Error(w, "credentialId, key, and token are required", http.StatusBadRequest)
		return
	}
	var serviceToStore *config.ServiceConfig
	if req.Service != nil {
		service := *req.Service
		if service.OAuth != nil && service.OAuth.CredentialID == "" {
			service.OAuth.CredentialID = req.CredentialID
		}
		normalized, err := serviceinfo.Normalize(req.CredentialID, service)
		if err != nil {
			http.Error(w, "invalid service metadata: "+err.Error(), http.StatusBadRequest)
			return
		}
		serviceToStore = &normalized
	}
	if err := h.secrets.Put(r.Context(), req.CredentialID, req.Key, value); err != nil {
		h.logger.Error("failed to store token", "error", err, "credential_id", req.CredentialID, "key", req.Key)
		http.Error(w, "failed to store token", http.StatusBadGateway)
		return
	}
	if serviceToStore != nil {
		if err := serviceinfo.Put(r.Context(), h.secrets, req.CredentialID, *serviceToStore); err != nil {
			h.logger.Error("failed to store service metadata", "error", err, "credential_id", req.CredentialID)
			http.Error(w, "failed to store service metadata", http.StatusBadRequest)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAdminTokenRequest(w, r)
	if !ok {
		return
	}
	if req.CredentialID == "" {
		http.Error(w, "credentialId is required", http.StatusBadRequest)
		return
	}
	cfg := h.store.Get()
	cred, ok := config.CredentialByID(cfg, req.CredentialID)
	if !ok {
		http.Error(w, "unknown credential", http.StatusBadRequest)
		return
	}
	brokerURL := config.HeaderValueFromEnv(cred.Params["revoke_broker_url"])
	if brokerURL == "" {
		http.Error(w, "credential requires revoke_broker_url", http.StatusBadRequest)
		return
	}
	storageID := strings.TrimSpace(req.User)
	if storageID == "" {
		storageID = config.CredentialUserID(cfg, cred)
	}
	key, token, found, err := h.adminTokenToRevoke(r.Context(), cfg, cred, storageID, req.Key)
	if err != nil {
		h.logger.Error("failed to read token for revoke", "error", err, "credential_id", req.CredentialID, "key", req.Key)
		http.Error(w, "failed to read token", http.StatusBadGateway)
		return
	}
	if !found {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	if err := h.revokeTokenWithBroker(r.Context(), cred, brokerURL, key, token); err != nil {
		h.logger.Error("failed to revoke token", "error", err, "credential_id", req.CredentialID, "key", key)
		http.Error(w, "failed to revoke token", http.StatusBadGateway)
		return
	}
	if err := h.secrets.Delete(r.Context(), storageID, adminTokenStorageKey(cfg, storageID, req.CredentialID, key)); err != nil {
		h.logger.Error("failed to delete revoked token", "error", err, "credential_id", req.CredentialID, "key", key)
		http.Error(w, "failed to delete revoked token", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) adminTokenToRevoke(ctx context.Context, cfg *config.Config, cred config.CredentialConfig, storageID, requestedKey string) (string, string, bool, error) {
	keys := []string{strings.TrimSpace(requestedKey)}
	if keys[0] == "" {
		keys = []string{"refresh_token", "access_token"}
	}
	for _, key := range keys {
		storageKey := adminTokenStorageKey(cfg, storageID, cred.ID, key)
		value, ok, err := h.secrets.Get(ctx, storageID, storageKey)
		if err != nil {
			return "", "", false, err
		}
		if ok {
			return key, value, true, nil
		}
		if storageKey != key && key == "refresh_token" && strings.HasSuffix(cred.ID, ".google") {
			value, ok, err := h.secrets.Get(ctx, storageID, key)
			if err != nil {
				return "", "", false, err
			}
			if ok {
				return key, value, true, nil
			}
		}
	}
	return "", "", false, nil
}

func (h *Handler) revokeTokenWithBroker(ctx context.Context, cred config.CredentialConfig, brokerURL, key, token string) error {
	form := url.Values{}
	form.Set("credential_id", cred.ID)
	form.Set("credential_type", cred.Type)
	form.Set("token", token)
	form.Set("token_type_hint", key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	brokerToken := config.HeaderValueFromEnv(cred.Params["revoke_broker_token"])
	if brokerToken == "" {
		brokerToken = config.HeaderValueFromEnv(cred.Params["token_broker_token"])
	}
	if brokerToken != "" {
		req.Header.Set("Authorization", "Bearer "+brokerToken)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("revoke broker returned %s", resp.Status)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	var brokerResp struct {
		OK        *bool  `json:"ok"`
		Error     string `json:"error"`
		ErrorDesc string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &brokerResp); err != nil {
		return nil
	}
	if brokerResp.OK != nil && !*brokerResp.OK {
		if brokerResp.Error != "" {
			return fmt.Errorf("%s: %s", brokerResp.Error, brokerResp.ErrorDesc)
		}
		return errors.New("revoke broker returned ok=false")
	}
	return nil
}

type adminTokenRequest struct {
	CredentialID      string                `json:"credentialId"`
	CredentialIDSnake string                `json:"credential_id"`
	Key               string                `json:"key"`
	Token             string                `json:"token"`
	Value             string                `json:"value"`
	User              string                `json:"user"`
	Service           *config.ServiceConfig `json:"service"`
}

type adminCredentialStatusResponse struct {
	Credentials []adminCredentialStatus `json:"credentials"`
}

type adminCredentialStatus struct {
	CredentialID  string `json:"credential_id"`
	Authenticated bool   `json:"authenticated"`
}

func decodeAdminTokenRequest(w http.ResponseWriter, r *http.Request) (adminTokenRequest, bool) {
	var req adminTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return adminTokenRequest{}, false
	}
	req.CredentialID = strings.TrimSpace(req.CredentialID)
	if req.CredentialID == "" {
		req.CredentialID = strings.TrimSpace(req.CredentialIDSnake)
	}
	req.Key = strings.TrimSpace(req.Key)
	req.User = strings.TrimSpace(req.User)
	return req, true
}

func (r adminTokenRequest) value() string {
	if r.Token != "" {
		return r.Token
	}
	return r.Value
}

func adminTokenStorageKey(cfg *config.Config, storageID, credentialID, key string) string {
	if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(storageID) && credentialID != "" {
		return credentialID + "." + key
	}
	return key
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
