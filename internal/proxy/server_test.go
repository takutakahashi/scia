package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/takutakahashi/scia/internal/approval"
	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

func TestForwardProxyInjectsCredential(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	proxyServer := newTestProxy(t, fmt.Sprintf(`
credentials:
  - id: upstream-token
    type: bearer
    value: test-token
rules:
  - name: inject-all
    hosts: ["%s"]
    action: allow
    credentials: ["upstream-token"]
`, mustParseURL(t, upstream.URL).Host))
	defer proxyServer.Close()

	client := proxiedClient(t, proxyServer.URL)
	resp, err := client.Get(upstream.URL + "/v1/items")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
}

func TestForwardProxyDeniesByPolicy(t *testing.T) {
	var called atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
	}))
	defer upstream.Close()

	proxyServer := newTestProxy(t, fmt.Sprintf(`
rules:
  - name: deny-delete
    hosts: ["%s"]
    methods: ["DELETE"]
    paths: ["/admin/*"]
    action: deny
`, mustParseURL(t, upstream.URL).Host))
	defer proxyServer.Close()

	client := proxiedClient(t, proxyServer.URL)
	req, err := http.NewRequest(http.MethodDelete, upstream.URL+"/admin/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
	if called.Load() {
		t.Fatal("upstream should not be called")
	}
}

func TestMITMConnectInjectsCredentialIntoHTTPSRequest(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mitm-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL := mustParseURL(t, upstream.URL)
	proxyServer, cfgPath := newTestProxyWithPath(t, fmt.Sprintf(`
server:
  mitm:
    caCertPath: "%s"
    caKeyPath: "%s"
credentials:
  - id: upstream-token
    type: bearer
    value: mitm-token
rules:
  - name: inject-https
    hosts: ["%s"]
    methods: ["GET"]
    paths: ["/secure"]
    action: allow
    credentials: ["upstream-token"]
`, filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "ca-key.pem"), upstreamURL.Hostname()))
	defer proxyServer.Close()
	proxyServer.Config.Handler.(*Handler).transport = upstream.Client().Transport.(*http.Transport).Clone()

	cfg := loadTestConfig(t, cfgPath)
	certPEM, err := os.ReadFile(cfg.Server.MITM.CACertPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append scia ca")
	}
	proxyURL := mustParseURL(t, proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
	}}

	resp, err := client.Get("https://" + upstreamURL.Host + "/secure")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status: %s body=%s", resp.Status, string(body))
	}
}

func TestMITMConnectForcesHTTP1Upstream(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Fatalf("expected upstream HTTP/1.x, got %s", r.Proto)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	upstreamURL := mustParseURL(t, upstream.URL)
	proxyServer, cfgPath := newTestProxyWithPath(t, fmt.Sprintf(`
server:
  mitm:
    caCertPath: "%s"
    caKeyPath: "%s"
rules:
  - name: allow-http2-capable-upstream
    hosts: ["%s"]
    methods: ["GET"]
    paths: ["/secure"]
    action: allow
`, filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "ca-key.pem"), upstreamURL.Hostname()))
	defer proxyServer.Close()
	handler := proxyServer.Config.Handler.(*Handler)
	handler.transport.TLSClientConfig = upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	cfg := loadTestConfig(t, cfgPath)
	certPEM, err := os.ReadFile(cfg.Server.MITM.CACertPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append scia ca")
	}
	proxyURL := mustParseURL(t, proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: roots,
		},
	}}

	resp, err := client.Get("https://" + upstreamURL.Host + "/secure")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
}

func TestForwardProxyUsesConfiguredBackendProxy(t *testing.T) {
	var called atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		if !r.URL.IsAbs() {
			t.Fatalf("backend proxy expected absolute-form URL, got %q", r.URL.String())
		}
		if got := r.URL.Host; got != "api.example.test" {
			t.Fatalf("unexpected target host: %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer backend-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	proxyServer := newTestProxy(t, fmt.Sprintf(`
server:
  mitm:
    caCertPath: "%s"
    caKeyPath: "%s"
  backendProxy:
    url: "%s"
credentials:
  - id: backend-token
    type: bearer
    value: backend-token
rules:
  - name: inject-through-backend
    hosts: ["api.example.test"]
    methods: ["GET"]
    paths: ["/v1/items"]
    action: allow
    credentials: ["backend-token"]
`, filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "ca-key.pem"), backend.URL))
	defer proxyServer.Close()

	client := proxiedClient(t, proxyServer.URL)
	resp, err := client.Get("http://api.example.test/v1/items")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
	if !called.Load() {
		t.Fatal("backend proxy was not called")
	}
}

func TestMITMConnectProxiesWebSocketThroughBackendProxy(t *testing.T) {
	var backendCalled atomic.Bool
	var upstreamSawCredential atomic.Bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			t.Fatalf("expected websocket upgrade, got headers: %#v", r.Header)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer websocket-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		upstreamSawCredential.Store(true)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "ping" {
			t.Fatalf("unexpected websocket payload: %q", string(buf))
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			t.Fatal(err)
		}
	}))
	defer upstream.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Fatalf("backend expected CONNECT, got %s", r.Method)
		}
		backendCalled.Store(true)
		upstreamConn, err := net.Dial("tcp", r.Host)
		if err != nil {
			t.Fatal(err)
		}
		clientConn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		go func() {
			_, _ = io.Copy(upstreamConn, clientConn)
			_ = upstreamConn.Close()
		}()
		go func() {
			_, _ = io.Copy(clientConn, upstreamConn)
			_ = clientConn.Close()
		}()
	}))
	defer backend.Close()

	upstreamURL := mustParseURL(t, upstream.URL)
	proxyServer, cfgPath := newTestProxyWithPath(t, fmt.Sprintf(`
server:
  mitm:
    caCertPath: "%s"
    caKeyPath: "%s"
  backendProxy:
    url: "%s"
credentials:
  - id: websocket-token
    type: bearer
    value: websocket-token
rules:
  - name: inject-websocket
    hosts: ["%s"]
    methods: ["GET"]
    paths: ["/ws"]
    action: allow
    credentials: ["websocket-token"]
`, filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "ca-key.pem"), backend.URL, upstreamURL.Hostname()))
	defer proxyServer.Close()
	proxyServer.Config.Handler.(*Handler).transport = upstream.Client().Transport.(*http.Transport).Clone()

	cfg := loadTestConfig(t, cfgPath)
	certPEM, err := os.ReadFile(cfg.Server.MITM.CACertPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append scia ca")
	}

	proxyURL := mustParseURL(t, proxyServer.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatal(err)
	}
	connectResp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected CONNECT status: %s", connectResp.Status)
	}

	tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: upstreamURL.Hostname()})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer tlsConn.Close()
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	if _, err := fmt.Fprintf(tlsConn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", upstreamURL.Host, wsKey); err != nil {
		t.Fatal(err)
	}
	wsResp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if wsResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected websocket status: %s", wsResp.Status)
	}
	if got := wsResp.Header.Get("Sec-WebSocket-Accept"); got != websocketAccept(wsKey) {
		t.Fatalf("unexpected websocket accept header: %q", got)
	}
	if _, err := tlsConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("unexpected websocket response: %q", string(buf))
	}
	if !backendCalled.Load() {
		t.Fatal("backend proxy was not used")
	}
	if !upstreamSawCredential.Load() {
		t.Fatal("upstream did not receive injected credential")
	}
}

func newTestProxy(t *testing.T, cfg string) *httptest.Server {
	server, _ := newTestProxyWithPath(t, cfg)
	return server
}

func newTestProxyWithPath(t *testing.T, cfg string) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if !strings.Contains(cfg, "caCertPath:") {
		cfg = fmt.Sprintf(`
server:
  mitm:
    caCertPath: "%s"
    caKeyPath: "%s"
`, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")) + cfg
	}
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{}))
	store, err := config.NewStore(context.Background(), config.NewFileProvider(path, logger), logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(store, secrets.NoopStore{}, approval.NewManager(store.Get().Server.ApprovalTimeout.Duration), logger)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(handler), path
}

func loadTestConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.NewFileProvider(path, slog.Default()).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func proxiedClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	parsed := mustParseURL(t, proxyURL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed)}}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
