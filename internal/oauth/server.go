package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/takutakahashi/scia/internal/config"
)

const googleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"

type Server struct {
	store  *config.Store
	client *http.Client
	logger *slog.Logger
	states sync.Map
}

type stateInfo struct {
	CredentialID string
	CreatedAt    time.Time
}

func NewServer(store *config.Store, logger *slog.Logger) *Server {
	return &Server{
		store:  store,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/oauth/google/start", s.startGoogle)
	mux.HandleFunc("/oauth/google/callback", s.googleCallback)
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
	creds := googleCredentials(s.store.Get())
	data := struct {
		Credentials []config.CredentialConfig
	}{Credentials: creds}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexTemplate.Execute(w, data)
}

func (s *Server) startGoogle(w http.ResponseWriter, r *http.Request) {
	credentialID := r.URL.Query().Get("credential")
	cred, ok := config.CredentialByID(s.store.Get(), credentialID)
	if !ok || cred.Type != "google-oauth-refresh-token" {
		http.Error(w, "unknown google credential", http.StatusBadRequest)
		return
	}
	clientID := config.HeaderValueFromEnv(cred.Params["client_id"])
	if clientID == "" {
		http.Error(w, "credential is missing client_id", http.StatusBadRequest)
		return
	}
	scope := cred.Params["scope"]
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
	cred, ok := config.CredentialByID(s.store.Get(), info.CredentialID)
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
	data := struct {
		CredentialID string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
	}{
		CredentialID: info.CredentialID,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
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
	tokenURL := cred.Params["token_url"]
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", config.HeaderValueFromEnv(cred.Params["client_id"]))
	form.Set("client_secret", config.HeaderValueFromEnv(cred.Params["client_secret"]))
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

func googleCredentials(cfg *config.Config) []config.CredentialConfig {
	var creds []config.CredentialConfig
	for _, cred := range cfg.Credentials {
		if cred.Type == "google-oauth-refresh-token" {
			creds = append(creds, cred)
		}
	}
	return creds
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
  {{if .Credentials}}
    {{range .Credentials}}
      <div class="item">
        <div><strong>{{.ID}}</strong></div>
        <p class="muted"><code>{{.Params.scope}}</code></p>
        <a class="button" href="/oauth/google/start?credential={{.ID}}">Authorize with Google</a>
      </div>
    {{end}}
  {{else}}
    <p class="muted">No <code>google-oauth-refresh-token</code> credentials are configured.</p>
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
  <p>Add this value to <code>params.refresh_token</code> for the credential. Access token expires in {{.ExpiresIn}} seconds.</p>
</body>
</html>`))
