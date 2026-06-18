package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

const googleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
const googleTokenURL = "https://oauth2.googleapis.com/token"
const googleRevokeURL = "https://oauth2.googleapis.com/revoke"

type Server struct {
	store   *config.Store
	secrets secrets.Store
	client  *http.Client
	logger  *slog.Logger
	states  sync.Map
}

type stateInfo struct {
	CredentialID string
	CreatedAt    time.Time
}

type googleOption struct {
	CredentialID string
	Scope        string
	Source       string
}

func NewServer(store *config.Store, secretStore secrets.Store, logger *slog.Logger) *Server {
	if secretStore == nil {
		secretStore = secrets.NoopStore{}
	}
	return &Server{
		store:   store,
		secrets: secretStore,
		client:  &http.Client{Timeout: 10 * time.Second},
		logger:  logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/oauth/google/start", s.startGoogle)
	mux.HandleFunc("/oauth/google/callback", s.googleCallback)
	mux.HandleFunc("/oauth/", s.namespaceOAuth)
	return mux
}

func (s *Server) ListenAddr() string {
	if listen := s.store.Get().Server.OAuth.Listen; listen != "" {
		return listen
	}
	return "127.0.0.1:8081"
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	options := s.googleOptions(s.store.Get())
	data := struct {
		Options []googleOption
	}{Options: options}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexTemplate.Execute(w, data)
}

func (s *Server) startGoogle(w http.ResponseWriter, r *http.Request) {
	credentialID := r.URL.Query().Get("credential")
	cfg := s.store.Get()
	cred, ok := s.googleCredential(cfg, credentialID)
	if !ok {
		http.Error(w, "unknown google credential", http.StatusBadRequest)
		return
	}
	clientID, err := s.googleClientID(r.Context(), cfg, cred)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "credential is missing client_id", http.StatusBadRequest)
		return
	}
	scope := googleScope(cfg, cred)
	if scope == "" {
		scope = "openid email profile"
	}
	state, err := randomState()
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	s.states.Store(state, stateInfo{CredentialID: credentialID, CreatedAt: time.Now()})
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", s.redirectURL(r))
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")
	q.Set("state", state)
	http.Redirect(w, r, googleAuthURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	if errText := r.URL.Query().Get("error"); errText != "" {
		http.Error(w, errText, http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	rawInfo, ok := s.states.LoadAndDelete(state)
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	info := rawInfo.(stateInfo)
	if time.Since(info.CreatedAt) > 10*time.Minute {
		http.Error(w, "state expired", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	cfg := s.store.Get()
	cred, ok := s.googleCredential(cfg, info.CredentialID)
	if !ok {
		http.Error(w, "credential disappeared", http.StatusBadRequest)
		return
	}
	token, err := s.exchangeCode(r.Context(), r, cred, code)
	if err != nil {
		s.logger.Error("google oauth code exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	if err := s.secrets.Put(r.Context(), info.CredentialID, "refresh_token", token.RefreshToken); err != nil {
		s.logger.Error("failed to store google refresh token", "error", err, "credential", info.CredentialID)
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}
	data := struct {
		CredentialID string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		CredentialID: info.CredentialID,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
		Stored:       true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = callbackTemplate.Execute(w, data)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (s *Server) exchangeCode(ctx context.Context, r *http.Request, cred config.CredentialConfig, code string) (tokenResponse, error) {
	cfg := s.store.Get()
	tokenURL := cred.Params["token_url"]
	googleCfg, hasGoogleCfg := config.GoogleOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasGoogleCfg {
		tokenURL = googleCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	clientID, err := s.googleClientID(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	clientSecret, err := s.googleClientSecret(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", s.redirectURL(r))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	var body tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return tokenResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if body.Error != "" {
			return tokenResponse{}, fmt.Errorf("%s: %s", body.Error, body.ErrorDesc)
		}
		return tokenResponse{}, fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	if body.RefreshToken == "" {
		return tokenResponse{}, fmt.Errorf("google did not return a refresh_token; revoke access or use prompt=consent and try again")
	}
	return body, nil
}

func (s *Server) redirectURL(r *http.Request) string {
	if redirect := s.store.Get().Server.OAuth.RedirectURL; redirect != "" {
		return redirect
	}
	host := r.Host
	if host == "" {
		host = "localhost" + s.ListenAddr()
	}
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	return "http://" + host + "/oauth/google/callback"
}

func (s *Server) namespaceOAuth(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/oauth/"), "/")
	if len(parts) != 3 || parts[1] != "google" {
		http.NotFound(w, r)
		return
	}
	namespace, action := parts[0], parts[2]
	credentialID := config.NamespaceGoogleCredentialID(namespace)
	cfg := s.store.Get()
	googleCfg, ok := config.GoogleOAuthConfigForCredential(cfg, credentialID)
	if !ok {
		http.Error(w, "unknown google namespace", http.StatusNotFound)
		return
	}
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleAuthorizationURL(w, r, credentialID, googleCfg, false)
	case "start":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleAuthorizationURL(w, r, credentialID, googleCfg, true)
	case "token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleToken(w, r, googleCfg)
	case "revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleRevoke(w, r, googleCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceGoogleAuthorizationURL(w http.ResponseWriter, r *http.Request, credentialID string, googleCfg config.GoogleOAuthConfig, redirect bool) {
	clientID, err := s.googleClientValue(r.Context(), googleCfg.ClientID, googleCfg.ClientIDSecretRef)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "google namespace is missing client id", http.StatusBadRequest)
		return
	}
	authURL := googleCfg.AuthURL
	if authURL == "" {
		authURL = googleAuthURL
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = googleCfg.RedirectURL
	}
	if redirectURI == "" {
		redirectURI = s.redirectURL(r)
	}
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = googleCfg.Scope
	}
	if scope == "" {
		scope = "openid email profile"
	}
	state := r.URL.Query().Get("state")
	if state == "" && redirect {
		generated, err := randomState()
		if err != nil {
			http.Error(w, "failed to create state", http.StatusInternalServerError)
			return
		}
		state = generated
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("access_type", queryDefault(r, "access_type", "offline"))
	q.Set("prompt", queryDefault(r, "prompt", "consent"))
	if state != "" {
		q.Set("state", state)
	}
	location := authURL + "?" + q.Encode()
	if redirect {
		s.states.Store(state, stateInfo{CredentialID: credentialID, CreatedAt: time.Now()})
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"credential_id":     credentialID,
		"authorization_url": location,
		"auth_url":          authURL,
		"redirect_uri":      redirectURI,
		"scope":             scope,
	})
}

func (s *Server) namespaceGoogleToken(w http.ResponseWriter, r *http.Request, googleCfg config.GoogleOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	grantType := form.Get("grant_type")
	if grantType == "" {
		grantType = "refresh_token"
	}
	if grantType != "refresh_token" && grantType != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, err := s.googleClientPair(r.Context(), googleCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstream := url.Values{}
	upstream.Set("grant_type", grantType)
	upstream.Set("client_id", clientID)
	upstream.Set("client_secret", clientSecret)
	if grantType == "refresh_token" {
		if form.Get("refresh_token") == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}
		upstream.Set("refresh_token", form.Get("refresh_token"))
	} else {
		if form.Get("code") == "" || form.Get("redirect_uri") == "" {
			http.Error(w, "code and redirect_uri are required", http.StatusBadRequest)
			return
		}
		upstream.Set("code", form.Get("code"))
		upstream.Set("redirect_uri", form.Get("redirect_uri"))
	}
	if scope := form.Get("scope"); scope != "" {
		upstream.Set("scope", scope)
	}
	tokenURL := googleCfg.TokenURL
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	s.forwardForm(w, r, tokenURL, upstream)
}

func (s *Server) namespaceGoogleRevoke(w http.ResponseWriter, r *http.Request, googleCfg config.GoogleOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if form.Get("token") == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	revokeURL := googleCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = googleRevokeURL
	}
	upstream := url.Values{}
	upstream.Set("token", form.Get("token"))
	s.forwardForm(w, r, revokeURL, upstream)
}

func (s *Server) forwardForm(w http.ResponseWriter, r *http.Request, endpoint string, form url.Values) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, value := range resp.Header.Values("Content-Type") {
		w.Header().Add("Content-Type", value)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) googleOptions(cfg *config.Config) []googleOption {
	var options []googleOption
	configID := cfg.GoogleOAuthCredentialID()
	hasConfigClient := cfg.Server.OAuth.Google.HasClientConfig()
	hasExplicitConfigCredential := false
	for _, cred := range cfg.Credentials {
		if cred.Type == "google-oauth-refresh-token" && cred.ID == configID {
			hasExplicitConfigCredential = true
			break
		}
	}
	if hasConfigClient && !hasExplicitConfigCredential {
		options = append(options, googleOption{
			CredentialID: configID,
			Scope:        googleScope(cfg, config.CredentialConfig{}),
			Source:       "server.oauth.google",
		})
	}
	for _, cred := range cfg.Credentials {
		if cred.Type == "google-oauth-refresh-token" {
			options = append(options, googleOption{
				CredentialID: cred.ID,
				Scope:        googleScope(cfg, cred),
				Source:       "credentials",
			})
		}
	}
	for namespace, ns := range cfg.Server.OAuth.Namespaces {
		if ns.Google.HasClientConfig() {
			options = append(options, googleOption{
				CredentialID: config.NamespaceGoogleCredentialID(namespace),
				Scope:        ns.Google.Scope,
				Source:       "server.oauth.namespaces." + namespace + ".google",
			})
		}
	}
	return options
}

func (s *Server) googleCredential(cfg *config.Config, credentialID string) (config.CredentialConfig, bool) {
	cred, ok := config.CredentialByID(cfg, credentialID)
	if !ok || cred.Type != "google-oauth-refresh-token" {
		return config.CredentialConfig{}, false
	}
	return cred, true
}

func (s *Server) googleClientID(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_id"]); value != "" {
		return value, nil
	}
	googleCfg, ok := config.GoogleOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.googleClientValue(ctx, googleCfg.ClientID, googleCfg.ClientIDSecretRef)
}

func (s *Server) googleClientSecret(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_secret"]); value != "" {
		return value, nil
	}
	googleCfg, ok := config.GoogleOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.googleClientValue(ctx, googleCfg.ClientSecret, googleCfg.ClientSecretRef)
}

func (s *Server) googleClientPair(ctx context.Context, googleCfg config.GoogleOAuthConfig) (string, string, error) {
	clientID, err := s.googleClientValue(ctx, googleCfg.ClientID, googleCfg.ClientIDSecretRef)
	if err != nil {
		return "", "", err
	}
	clientSecret, err := s.googleClientValue(ctx, googleCfg.ClientSecret, googleCfg.ClientSecretRef)
	if err != nil {
		return "", "", err
	}
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("google namespace requires client id and client secret")
	}
	return clientID, clientSecret, nil
}

func (s *Server) googleClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	credentialID, key, err := config.SecretRefParts(secretRef)
	if err != nil {
		return "", err
	}
	value, ok, err := s.secrets.Get(ctx, credentialID, key)
	if err != nil {
		return "", err
	}
	if ok {
		return value, nil
	}
	return "", nil
}

func googleScope(cfg *config.Config, cred config.CredentialConfig) string {
	if cred.Params["scope"] != "" {
		return cred.Params["scope"]
	}
	googleCfg, ok := config.GoogleOAuthConfigForCredential(cfg, cred.ID)
	if ok {
		return googleCfg.Scope
	}
	return ""
}

func queryDefault(r *http.Request, key, fallback string) string {
	if value := r.URL.Query().Get(key); value != "" {
		return value
	}
	return fallback
}

func parseFormOrJSON(r *http.Request) (url.Values, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		values := url.Values{}
		for key, value := range body {
			values.Set(key, value)
		}
		return values, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return r.PostForm, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomState() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func NormalizeListenForDisplay(addr string) string {
	if addr == "" {
		return "http://localhost:8081"
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "localhost"
		}
		return "http://" + net.JoinHostPort(host, port)
	}
	return "http://" + addr
}

var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>scia OAuth</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 20px; color: #17202a; }
    h1 { font-size: 24px; margin-bottom: 8px; }
    .item { border: 1px solid #d7dde5; border-radius: 8px; padding: 16px; margin: 12px 0; }
    .muted { color: #5f6b7a; }
    a.button { display: inline-block; padding: 8px 12px; background: #1a73e8; color: white; border-radius: 6px; text-decoration: none; }
    code { background: #f3f5f7; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>scia OAuth</h1>
  {{if .Options}}
    {{range .Options}}
      <div class="item">
        <div><strong>{{.CredentialID}}</strong></div>
        <p class="muted"><code>{{.Scope}}</code></p>
        <p class="muted">{{.Source}}</p>
        <a class="button" href="/oauth/google/start?credential={{.CredentialID}}">Authorize with Google</a>
      </div>
    {{end}}
  {{else}}
    <p class="muted">No Google OAuth client is configured.</p>
  {{end}}
</body>
</html>`))

var callbackTemplate = template.Must(template.New("callback").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>scia OAuth Complete</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 20px; color: #17202a; }
    textarea { width: 100%; min-height: 180px; font-family: ui-monospace, monospace; font-size: 13px; }
    code { background: #f3f5f7; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Google OAuth Complete</h1>
  <p>Credential: <code>{{.CredentialID}}</code></p>
  <textarea readonly>refresh_token: "{{.RefreshToken}}"</textarea>
  {{if .Stored}}<p>The refresh token was stored in the configured scia secret store.</p>{{end}}
  <p>You can also copy this value into <code>params.refresh_token</code>. Access token expires in {{.ExpiresIn}} seconds.</p>
</body>
</html>`))
