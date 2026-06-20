package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
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
const notionAuthURL = "https://api.notion.com/v1/oauth/authorize"
const notionTokenURL = "https://api.notion.com/v1/oauth/token"
const notionRevokeURL = "https://api.notion.com/v1/oauth/revoke"
const notionVersion = "2026-03-11"
const slackAuthURL = "https://slack.com/oauth/v2/authorize"
const slackTokenURL = "https://slack.com/api/oauth.v2.access"
const slackRevokeURL = "https://slack.com/api/auth.revoke"

type Server struct {
	store   *config.Store
	secrets secrets.Store
	client  *http.Client
	logger  *slog.Logger
	states  sync.Map
}

type stateInfo struct {
	User         string
	CredentialID string
	CreatedAt    time.Time
}

type googleOption struct {
	User         string
	CredentialID string
	Scope        string
	Source       string
}

type notionOption struct {
	User         string
	CredentialID string
	Source       string
}

type slackOption struct {
	User         string
	CredentialID string
	Scope        string
	UserScope    string
	TokenType    string
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
	mux.HandleFunc("/_scia/healthz", s.healthz)
	mux.HandleFunc("/oauth/google/start", s.startGoogle)
	mux.HandleFunc("/oauth/google/callback", s.googleCallback)
	mux.HandleFunc("/oauth/notion/start", s.startNotion)
	mux.HandleFunc("/oauth/notion/callback", s.notionCallback)
	mux.HandleFunc("/oauth/slack/start", s.startSlack)
	mux.HandleFunc("/oauth/slack/callback", s.slackCallback)
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
		GoogleOptions []googleOption
		NotionOptions []notionOption
		SlackOptions  []slackOption
	}{GoogleOptions: options, NotionOptions: s.notionOptions(s.store.Get()), SlackOptions: s.slackOptions(s.store.Get())}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexTemplate.Execute(w, data)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) startGoogle(w http.ResponseWriter, r *http.Request) {
	credentialID := r.URL.Query().Get("credential")
	userID := r.URL.Query().Get("user")
	cfg := s.store.Get()
	if cfg.Server.Secrets.Mode == "kubernetes" {
		if userID == "" {
			http.Error(w, "user is required in kubernetes mode", http.StatusBadRequest)
			return
		}
		if !cfg.HasUser(userID) {
			http.Error(w, "unknown user", http.StatusBadRequest)
			return
		}
	}
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
	s.states.Store(state, stateInfo{User: userID, CredentialID: credentialID, CreatedAt: time.Now()})
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
	if err := s.secrets.Put(r.Context(), s.storageUserID(cfg, info), "refresh_token", token.RefreshToken); err != nil {
		s.logger.Error("failed to store google refresh token", "error", err, "credential", info.CredentialID, "user", info.User)
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "Google",
		User:         info.User,
		CredentialID: info.CredentialID,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
		Stored:       true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = callbackTemplate.Execute(w, data)
}

func (s *Server) startNotion(w http.ResponseWriter, r *http.Request) {
	credentialID := r.URL.Query().Get("credential")
	userID := r.URL.Query().Get("user")
	cfg := s.store.Get()
	if cfg.Server.Secrets.Mode == "kubernetes" {
		if userID == "" {
			http.Error(w, "user is required in kubernetes mode", http.StatusBadRequest)
			return
		}
		if !cfg.HasUser(userID) {
			http.Error(w, "unknown user", http.StatusBadRequest)
			return
		}
	}
	cred, ok := s.notionCredential(cfg, credentialID)
	if !ok {
		http.Error(w, "unknown notion credential", http.StatusBadRequest)
		return
	}
	clientID, err := s.notionClientID(r.Context(), cfg, cred)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "credential is missing client_id", http.StatusBadRequest)
		return
	}
	state, err := randomState()
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	s.states.Store(state, stateInfo{User: userID, CredentialID: credentialID, CreatedAt: time.Now()})
	authURL := notionAuthURL
	if notionCfg, ok := config.NotionOAuthConfigForCredential(cfg, cred.ID); ok && notionCfg.AuthURL != "" {
		authURL = notionCfg.AuthURL
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", s.providerRedirectURL(r, "notion"))
	q.Set("response_type", "code")
	q.Set("owner", "user")
	q.Set("state", state)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) notionCallback(w http.ResponseWriter, r *http.Request) {
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
	cred, ok := s.notionCredential(cfg, info.CredentialID)
	if !ok {
		http.Error(w, "credential disappeared", http.StatusBadRequest)
		return
	}
	token, err := s.exchangeNotionCode(r.Context(), r, cred, code)
	if err != nil {
		s.logger.Error("notion oauth code exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	if err := s.secrets.Put(r.Context(), s.storageUserID(cfg, info), "refresh_token", token.RefreshToken); err != nil {
		s.logger.Error("failed to store notion refresh token", "error", err, "credential", info.CredentialID, "user", info.User)
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "Notion",
		User:         info.User,
		CredentialID: info.CredentialID,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
		Stored:       true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = callbackTemplate.Execute(w, data)
}

func (s *Server) startSlack(w http.ResponseWriter, r *http.Request) {
	credentialID := r.URL.Query().Get("credential")
	userID := r.URL.Query().Get("user")
	cfg := s.store.Get()
	if cfg.Server.Secrets.Mode == "kubernetes" {
		if userID == "" {
			http.Error(w, "user is required in kubernetes mode", http.StatusBadRequest)
			return
		}
		if !cfg.HasUser(userID) {
			http.Error(w, "unknown user", http.StatusBadRequest)
			return
		}
	}
	cred, ok := s.slackCredential(cfg, credentialID)
	if !ok {
		http.Error(w, "unknown slack credential", http.StatusBadRequest)
		return
	}
	clientID, err := s.slackClientID(r.Context(), cfg, cred)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "credential is missing client_id", http.StatusBadRequest)
		return
	}
	state, err := randomState()
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	s.states.Store(state, stateInfo{User: userID, CredentialID: credentialID, CreatedAt: time.Now()})
	authURL := slackAuthURL
	if slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID); ok && slackCfg.AuthURL != "" {
		authURL = slackCfg.AuthURL
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", s.providerRedirectURL(r, "slack"))
	scope := slackScope(cfg, cred)
	userScope := slackUserScope(cfg, cred)
	if scope != "" {
		q.Set("scope", scope)
	}
	if userScope != "" {
		q.Set("user_scope", userScope)
	}
	q.Set("state", state)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) slackCallback(w http.ResponseWriter, r *http.Request) {
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
	cred, ok := s.slackCredential(cfg, info.CredentialID)
	if !ok {
		http.Error(w, "credential disappeared", http.StatusBadRequest)
		return
	}
	token, err := s.exchangeSlackCode(r.Context(), r, cred, code)
	if err != nil {
		s.logger.Error("slack oauth code exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	storageID := s.storageUserID(cfg, info)
	selected, err := selectSlackToken(cfg, cred, token)
	if err != nil {
		s.logger.Error("slack oauth token selection failed", "error", err, "credential", info.CredentialID, "user", info.User)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := s.secrets.Put(r.Context(), storageID, "access_token", selected.AccessToken); err != nil {
		s.logger.Error("failed to store slack access token", "error", err, "credential", info.CredentialID, "user", info.User)
		http.Error(w, "failed to store access token", http.StatusInternalServerError)
		return
	}
	if selected.RefreshToken != "" {
		if err := s.secrets.Put(r.Context(), storageID, "refresh_token", selected.RefreshToken); err != nil {
			s.logger.Error("failed to store slack refresh token", "error", err, "credential", info.CredentialID, "user", info.User)
			http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
			return
		}
	}
	if selected.Scope != "" {
		if err := s.secrets.Put(r.Context(), storageID, "scope", selected.Scope); err != nil {
			s.logger.Error("failed to store slack token scope", "error", err, "credential", info.CredentialID, "user", info.User)
			http.Error(w, "failed to store token scope", http.StatusInternalServerError)
			return
		}
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "Slack",
		User:         info.User,
		CredentialID: info.CredentialID,
		RefreshToken: selected.RefreshToken,
		AccessToken:  selected.AccessToken,
		ExpiresIn:    selected.ExpiresIn,
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

type slackTokenResponse struct {
	OK           *bool           `json:"ok"`
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	TokenType    string          `json:"token_type"`
	Scope        string          `json:"scope"`
	ExpiresIn    int64           `json:"expires_in"`
	AuthedUser   slackAuthedUser `json:"authed_user"`
	Error        string          `json:"error"`
	ErrorDesc    string          `json:"error_description"`
}

type slackAuthedUser struct {
	ID           string `json:"id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

type selectedSlackToken struct {
	AccessToken  string
	RefreshToken string
	Scope        string
	ExpiresIn    int64
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

func (s *Server) exchangeNotionCode(ctx context.Context, r *http.Request, cred config.CredentialConfig, code string) (tokenResponse, error) {
	cfg := s.store.Get()
	tokenURL := cred.Params["token_url"]
	notionCfg, hasNotionCfg := config.NotionOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasNotionCfg {
		tokenURL = notionCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = notionTokenURL
	}
	clientID, err := s.notionClientID(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	clientSecret, err := s.notionClientSecret(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	body, err := json.Marshal(map[string]string{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": s.providerRedirectURL(r, "notion"),
	})
	if err != nil {
		return tokenResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(body))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Notion-Version", notionConfigVersion(notionCfg))
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := s.client.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return tokenResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if token.Error != "" {
			return tokenResponse{}, fmt.Errorf("%s: %s", token.Error, token.ErrorDesc)
		}
		return tokenResponse{}, fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	if token.RefreshToken == "" {
		return tokenResponse{}, fmt.Errorf("notion did not return a refresh_token")
	}
	return token, nil
}

func (s *Server) exchangeSlackCode(ctx context.Context, r *http.Request, cred config.CredentialConfig, code string) (slackTokenResponse, error) {
	cfg := s.store.Get()
	tokenURL := cred.Params["token_url"]
	slackCfg, hasSlackCfg := config.SlackOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasSlackCfg {
		tokenURL = slackCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = slackTokenURL
	}
	clientID, err := s.slackClientID(ctx, cfg, cred)
	if err != nil {
		return slackTokenResponse{}, err
	}
	clientSecret, err := s.slackClientSecret(ctx, cfg, cred)
	if err != nil {
		return slackTokenResponse{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", s.providerRedirectURL(r, "slack"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return slackTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return slackTokenResponse{}, err
	}
	defer resp.Body.Close()
	var token slackTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return slackTokenResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if token.Error != "" {
			return slackTokenResponse{}, fmt.Errorf("%s: %s", token.Error, token.ErrorDesc)
		}
		return slackTokenResponse{}, fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	if token.OK != nil && !*token.OK {
		if token.Error != "" {
			return slackTokenResponse{}, fmt.Errorf("%s: %s", token.Error, token.ErrorDesc)
		}
		return slackTokenResponse{}, fmt.Errorf("slack token endpoint returned ok=false")
	}
	return token, nil
}

func selectSlackToken(cfg *config.Config, cred config.CredentialConfig, token slackTokenResponse) (selectedSlackToken, error) {
	switch slackTokenType(cfg, cred) {
	case "user":
		if token.AuthedUser.AccessToken == "" {
			return selectedSlackToken{}, fmt.Errorf("slack response did not include authed_user.access_token")
		}
		return selectedSlackToken{
			AccessToken:  token.AuthedUser.AccessToken,
			RefreshToken: token.AuthedUser.RefreshToken,
			Scope:        token.AuthedUser.Scope,
			ExpiresIn:    token.AuthedUser.ExpiresIn,
		}, nil
	case "bot":
		if token.AccessToken == "" {
			return selectedSlackToken{}, fmt.Errorf("slack response did not include access_token")
		}
		return selectedSlackToken{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Scope:        token.Scope,
			ExpiresIn:    token.ExpiresIn,
		}, nil
	default:
		return selectedSlackToken{}, fmt.Errorf("unsupported slack token_type %q", slackTokenType(cfg, cred))
	}
}

func (s *Server) redirectURL(r *http.Request) string {
	return s.providerRedirectURL(r, "google")
}

func (s *Server) providerRedirectURL(r *http.Request, provider string) string {
	cfg := s.store.Get()
	switch provider {
	case "google":
		if redirect := cfg.Server.OAuth.Google.RedirectURL; redirect != "" {
			return redirect
		}
	case "notion":
		if redirect := cfg.Server.OAuth.Notion.RedirectURL; redirect != "" {
			return redirect
		}
	case "slack":
		if redirect := cfg.Server.OAuth.Slack.RedirectURL; redirect != "" {
			return redirect
		}
	}
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
	return "http://" + host + "/oauth/" + provider + "/callback"
}

func (s *Server) namespaceOAuth(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/oauth/"), "/")
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}
	namespace, provider, action := parts[0], parts[1], parts[2]
	cfg := s.store.Get()
	if requiresBrokerAuth(action) && !s.authorizeBrokerRequest(w, r, cfg) {
		return
	}
	switch provider {
	case "google":
		credentialID := config.NamespaceGoogleCredentialID(namespace)
		googleCfg, ok := config.GoogleOAuthConfigForCredential(cfg, credentialID)
		if !ok {
			http.Error(w, "unknown google namespace", http.StatusNotFound)
			return
		}
		s.namespaceGoogleOAuth(w, r, namespace, credentialID, action, googleCfg)
	case "notion":
		credentialID := config.NamespaceNotionCredentialID(namespace)
		notionCfg, ok := config.NotionOAuthConfigForCredential(cfg, credentialID)
		if !ok {
			http.Error(w, "unknown notion namespace", http.StatusNotFound)
			return
		}
		s.namespaceNotionOAuth(w, r, namespace, credentialID, action, notionCfg)
	case "slack":
		credentialID := config.NamespaceSlackCredentialID(namespace)
		slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, credentialID)
		if !ok {
			http.Error(w, "unknown slack namespace", http.StatusNotFound)
			return
		}
		s.namespaceSlackOAuth(w, r, namespace, credentialID, action, slackCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceGoogleOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, googleCfg config.GoogleOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleAuthorizationURL(w, r, namespace, credentialID, googleCfg, false)
	case "start":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleAuthorizationURL(w, r, namespace, credentialID, googleCfg, true)
	case "token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleToken(w, r, googleCfg)
	case "access-token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGoogleAccessToken(w, r, namespace, credentialID, googleCfg)
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

func (s *Server) namespaceNotionOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, notionCfg config.NotionOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceNotionAuthorizationURL(w, r, namespace, credentialID, notionCfg, false)
	case "start":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceNotionAuthorizationURL(w, r, namespace, credentialID, notionCfg, true)
	case "token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceNotionToken(w, r, notionCfg)
	case "access-token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceNotionAccessToken(w, r, namespace, credentialID, notionCfg)
	case "revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceNotionRevoke(w, r, notionCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceSlackOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, slackCfg config.SlackOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceSlackAuthorizationURL(w, r, namespace, credentialID, slackCfg, false)
	case "start":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceSlackAuthorizationURL(w, r, namespace, credentialID, slackCfg, true)
	case "token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceSlackToken(w, r, slackCfg)
	case "access-token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceSlackAccessToken(w, r, namespace, credentialID)
	case "revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceSlackRevoke(w, r, slackCfg)
	default:
		http.NotFound(w, r)
	}
}

func requiresBrokerAuth(action string) bool {
	switch action {
	case "authorization-url", "token", "access-token", "revoke":
		return true
	default:
		return false
	}
}

func (s *Server) authorizeBrokerRequest(w http.ResponseWriter, r *http.Request, cfg *config.Config) bool {
	expected := config.HeaderValueFromEnv(cfg.Server.OAuth.BrokerToken)
	if expected == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scia-oauth-broker"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scia-oauth-broker"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) namespaceGoogleAuthorizationURL(w http.ResponseWriter, r *http.Request, namespace, credentialID string, googleCfg config.GoogleOAuthConfig, redirect bool) {
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
		s.states.Store(state, stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
			CreatedAt:    time.Now(),
		})
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

func (s *Server) namespaceNotionAuthorizationURL(w http.ResponseWriter, r *http.Request, namespace, credentialID string, notionCfg config.NotionOAuthConfig, redirect bool) {
	clientID, err := s.notionClientValue(r.Context(), notionCfg.ClientID, notionCfg.ClientIDSecretRef)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "notion namespace is missing client id", http.StatusBadRequest)
		return
	}
	authURL := notionCfg.AuthURL
	if authURL == "" {
		authURL = notionAuthURL
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = notionCfg.RedirectURL
	}
	if redirectURI == "" {
		redirectURI = s.providerRedirectURL(r, "notion")
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
	q.Set("owner", "user")
	if state != "" {
		q.Set("state", state)
	}
	location := authURL + "?" + q.Encode()
	if redirect {
		s.states.Store(state, stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
			CreatedAt:    time.Now(),
		})
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"credential_id":     credentialID,
		"authorization_url": location,
		"auth_url":          authURL,
		"redirect_uri":      redirectURI,
	})
}

func (s *Server) namespaceSlackAuthorizationURL(w http.ResponseWriter, r *http.Request, namespace, credentialID string, slackCfg config.SlackOAuthConfig, redirect bool) {
	clientID, err := s.slackClientValue(r.Context(), slackCfg.ClientID, slackCfg.ClientIDSecretRef)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "slack namespace is missing client id", http.StatusBadRequest)
		return
	}
	authURL := slackCfg.AuthURL
	if authURL == "" {
		authURL = slackAuthURL
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = slackCfg.RedirectURL
	}
	if redirectURI == "" {
		redirectURI = s.providerRedirectURL(r, "slack")
	}
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = slackCfg.Scope
	}
	userScope := r.URL.Query().Get("user_scope")
	if userScope == "" {
		userScope = slackCfg.UserScope
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
	if scope != "" {
		q.Set("scope", scope)
	}
	if userScope != "" {
		q.Set("user_scope", userScope)
	}
	if state != "" {
		q.Set("state", state)
	}
	location := authURL + "?" + q.Encode()
	if redirect {
		s.states.Store(state, stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
			CreatedAt:    time.Now(),
		})
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"credential_id":     credentialID,
		"authorization_url": location,
		"auth_url":          authURL,
		"redirect_uri":      redirectURI,
		"scope":             scope,
		"user_scope":        userScope,
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

func (s *Server) namespaceGoogleAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string, googleCfg config.GoogleOAuthConfig) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	refreshToken, ok, err := s.secrets.Get(r.Context(), storageID, "refresh_token")
	if err != nil {
		s.logger.Error("failed to load google refresh token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load refresh token", http.StatusInternalServerError)
		return
	}
	if !ok || refreshToken == "" {
		http.Error(w, "refresh_token is not registered", http.StatusNotFound)
		return
	}
	clientID, clientSecret, err := s.googleClientPair(r.Context(), googleCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstream := url.Values{}
	upstream.Set("grant_type", "refresh_token")
	upstream.Set("client_id", clientID)
	upstream.Set("client_secret", clientSecret)
	upstream.Set("refresh_token", refreshToken)
	if scope := r.URL.Query().Get("scope"); scope != "" {
		upstream.Set("scope", scope)
	}
	tokenURL := googleCfg.TokenURL
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	s.forwardForm(w, r, tokenURL, upstream)
}

func (s *Server) namespaceNotionToken(w http.ResponseWriter, r *http.Request, notionCfg config.NotionOAuthConfig) {
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
	body := map[string]string{"grant_type": grantType}
	if grantType == "refresh_token" {
		if form.Get("refresh_token") == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}
		body["refresh_token"] = form.Get("refresh_token")
	} else {
		if form.Get("code") == "" || form.Get("redirect_uri") == "" {
			http.Error(w, "code and redirect_uri are required", http.StatusBadRequest)
			return
		}
		body["code"] = form.Get("code")
		body["redirect_uri"] = form.Get("redirect_uri")
	}
	tokenURL := notionCfg.TokenURL
	if tokenURL == "" {
		tokenURL = notionTokenURL
	}
	s.forwardNotionJSON(w, r, tokenURL, notionCfg, body, "")
}

func (s *Server) namespaceSlackToken(w http.ResponseWriter, r *http.Request, slackCfg config.SlackOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	grantType := form.Get("grant_type")
	if grantType == "" {
		grantType = "authorization_code"
	}
	if grantType != "authorization_code" && grantType != "refresh_token" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	clientID, err := s.slackClientValue(r.Context(), slackCfg.ClientID, slackCfg.ClientIDSecretRef)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientSecret, err := s.slackClientValue(r.Context(), slackCfg.ClientSecret, slackCfg.ClientSecretRef)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstream := url.Values{}
	upstream.Set("grant_type", grantType)
	upstream.Set("client_id", clientID)
	upstream.Set("client_secret", clientSecret)
	if grantType == "authorization_code" {
		if form.Get("code") == "" || form.Get("redirect_uri") == "" {
			http.Error(w, "code and redirect_uri are required", http.StatusBadRequest)
			return
		}
		upstream.Set("code", form.Get("code"))
		upstream.Set("redirect_uri", form.Get("redirect_uri"))
	} else {
		if form.Get("refresh_token") == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}
		upstream.Set("refresh_token", form.Get("refresh_token"))
	}
	tokenURL := slackCfg.TokenURL
	if tokenURL == "" {
		tokenURL = slackTokenURL
	}
	s.forwardForm(w, r, tokenURL, upstream)
}

func (s *Server) namespaceNotionAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string, notionCfg config.NotionOAuthConfig) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	refreshToken, ok, err := s.secrets.Get(r.Context(), storageID, "refresh_token")
	if err != nil {
		s.logger.Error("failed to load notion refresh token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load refresh token", http.StatusInternalServerError)
		return
	}
	if !ok || refreshToken == "" {
		http.Error(w, "refresh_token is not registered", http.StatusNotFound)
		return
	}
	tokenURL := notionCfg.TokenURL
	if tokenURL == "" {
		tokenURL = notionTokenURL
	}
	s.forwardNotionJSON(w, r, tokenURL, notionCfg, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}, storageID)
}

func (s *Server) namespaceSlackAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	accessToken, ok, err := s.secrets.Get(r.Context(), storageID, "access_token")
	if err != nil {
		s.logger.Error("failed to load slack access token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load access token", http.StatusInternalServerError)
		return
	}
	if !ok || accessToken == "" {
		http.Error(w, "access_token is not registered", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": accessToken,
		"token_type":   "Bearer",
	})
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

func (s *Server) namespaceNotionRevoke(w http.ResponseWriter, r *http.Request, notionCfg config.NotionOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if form.Get("token") == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	revokeURL := notionCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = notionRevokeURL
	}
	s.forwardNotionJSON(w, r, revokeURL, notionCfg, map[string]string{"token": form.Get("token")}, "")
}

func (s *Server) namespaceSlackRevoke(w http.ResponseWriter, r *http.Request, slackCfg config.SlackOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if form.Get("token") == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	revokeURL := slackCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = slackRevokeURL
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

func (s *Server) forwardNotionJSON(w http.ResponseWriter, r *http.Request, endpoint string, notionCfg config.NotionOAuthConfig, body map[string]string, storageID string) {
	clientID, clientSecret, err := s.notionClientPair(r.Context(), notionCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Notion-Version", notionConfigVersion(notionCfg))
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, value := range resp.Header.Values("Content-Type") {
		w.Header().Add("Content-Type", value)
	}
	if storageID == "" || resp.StatusCode < 200 || resp.StatusCode > 299 {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		http.Error(w, "failed to decode upstream token response", http.StatusBadGateway)
		return
	}
	if token.RefreshToken != "" {
		if err := s.secrets.Put(r.Context(), storageID, "refresh_token", token.RefreshToken); err != nil {
			s.logger.Error("failed to store rotated notion refresh token", "error", err, "storage", storageID)
			http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = json.NewEncoder(w).Encode(token)
}

func (s *Server) googleOptions(cfg *config.Config) []googleOption {
	var options []googleOption
	appendOption := func(userID, credentialID, scope, source string) {
		options = append(options, googleOption{
			User:         userID,
			CredentialID: credentialID,
			Scope:        scope,
			Source:       source,
		})
	}
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
		if cfg.Server.Secrets.Mode == "kubernetes" {
			for userID := range cfg.Server.Users {
				appendOption(userID, configID, googleScope(cfg, config.CredentialConfig{}), "server.oauth.google")
			}
		} else {
			appendOption("", configID, googleScope(cfg, config.CredentialConfig{}), "server.oauth.google")
		}
	}
	for _, cred := range cfg.Credentials {
		if cred.Type == "google-oauth-refresh-token" {
			userID := config.CredentialUserID(cfg, cred)
			if cfg.Server.Secrets.Mode == "kubernetes" && userID == cred.ID {
				for configuredUserID := range cfg.Server.Users {
					appendOption(configuredUserID, cred.ID, googleScope(cfg, cred), "credentials")
				}
				continue
			}
			appendOption(userID, cred.ID, googleScope(cfg, cred), "credentials")
		}
	}
	for namespace, ns := range cfg.Server.OAuth.Namespaces {
		if ns.Google.HasClientConfig() {
			credentialID := config.NamespaceGoogleCredentialID(namespace)
			if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(namespace) {
				appendOption(namespace, credentialID, ns.Google.Scope, "server.oauth.namespaces."+namespace+".google")
			} else if cfg.Server.Secrets.Mode != "kubernetes" {
				appendOption("", credentialID, ns.Google.Scope, "server.oauth.namespaces."+namespace+".google")
			}
		}
	}
	return options
}

func (s *Server) notionOptions(cfg *config.Config) []notionOption {
	var options []notionOption
	appendOption := func(userID, credentialID, source string) {
		options = append(options, notionOption{
			User:         userID,
			CredentialID: credentialID,
			Source:       source,
		})
	}
	configID := cfg.NotionOAuthCredentialID()
	hasConfigClient := cfg.Server.OAuth.Notion.HasClientConfig()
	hasExplicitConfigCredential := false
	for _, cred := range cfg.Credentials {
		if cred.Type == "notion-oauth-refresh-token" && cred.ID == configID {
			hasExplicitConfigCredential = true
			break
		}
	}
	if hasConfigClient && !hasExplicitConfigCredential {
		if cfg.Server.Secrets.Mode == "kubernetes" {
			for userID := range cfg.Server.Users {
				appendOption(userID, configID, "server.oauth.notion")
			}
		} else {
			appendOption("", configID, "server.oauth.notion")
		}
	}
	for _, cred := range cfg.Credentials {
		if cred.Type == "notion-oauth-refresh-token" {
			userID := config.CredentialUserID(cfg, cred)
			if cfg.Server.Secrets.Mode == "kubernetes" && userID == cred.ID {
				for configuredUserID := range cfg.Server.Users {
					appendOption(configuredUserID, cred.ID, "credentials")
				}
				continue
			}
			appendOption(userID, cred.ID, "credentials")
		}
	}
	for namespace, ns := range cfg.Server.OAuth.Namespaces {
		if ns.Notion.HasClientConfig() {
			credentialID := config.NamespaceNotionCredentialID(namespace)
			if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(namespace) {
				appendOption(namespace, credentialID, "server.oauth.namespaces."+namespace+".notion")
			} else if cfg.Server.Secrets.Mode != "kubernetes" {
				appendOption("", credentialID, "server.oauth.namespaces."+namespace+".notion")
			}
		}
	}
	return options
}

func (s *Server) slackOptions(cfg *config.Config) []slackOption {
	var options []slackOption
	appendOption := func(userID, credentialID, scope, userScope, tokenType, source string) {
		options = append(options, slackOption{
			User:         userID,
			CredentialID: credentialID,
			Scope:        scope,
			UserScope:    userScope,
			TokenType:    tokenType,
			Source:       source,
		})
	}
	configID := cfg.SlackOAuthCredentialID()
	hasConfigClient := cfg.Server.OAuth.Slack.HasClientConfig()
	hasExplicitConfigCredential := false
	for _, cred := range cfg.Credentials {
		if cred.Type == "slack-oauth-access-token" && cred.ID == configID {
			hasExplicitConfigCredential = true
			break
		}
	}
	if hasConfigClient && !hasExplicitConfigCredential {
		cred := config.CredentialConfig{ID: configID, Type: "slack-oauth-access-token", Params: map[string]string{}}
		if cfg.Server.Secrets.Mode == "kubernetes" {
			for userID := range cfg.Server.Users {
				appendOption(userID, configID, slackScope(cfg, cred), slackUserScope(cfg, cred), slackTokenType(cfg, cred), "server.oauth.slack")
			}
		} else {
			appendOption("", configID, slackScope(cfg, cred), slackUserScope(cfg, cred), slackTokenType(cfg, cred), "server.oauth.slack")
		}
	}
	for _, cred := range cfg.Credentials {
		if cred.Type == "slack-oauth-access-token" {
			userID := config.CredentialUserID(cfg, cred)
			if cfg.Server.Secrets.Mode == "kubernetes" && userID == cred.ID {
				for configuredUserID := range cfg.Server.Users {
					appendOption(configuredUserID, cred.ID, slackScope(cfg, cred), slackUserScope(cfg, cred), slackTokenType(cfg, cred), "credentials")
				}
				continue
			}
			appendOption(userID, cred.ID, slackScope(cfg, cred), slackUserScope(cfg, cred), slackTokenType(cfg, cred), "credentials")
		}
	}
	for namespace, ns := range cfg.Server.OAuth.Namespaces {
		if ns.Slack.HasClientConfig() {
			credentialID := config.NamespaceSlackCredentialID(namespace)
			cred := config.CredentialConfig{ID: credentialID, Type: "slack-oauth-access-token", Params: map[string]string{}}
			if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(namespace) {
				appendOption(namespace, credentialID, ns.Slack.Scope, ns.Slack.UserScope, slackTokenType(cfg, cred), "server.oauth.namespaces."+namespace+".slack")
			} else if cfg.Server.Secrets.Mode != "kubernetes" {
				appendOption("", credentialID, ns.Slack.Scope, ns.Slack.UserScope, slackTokenType(cfg, cred), "server.oauth.namespaces."+namespace+".slack")
			}
		}
	}
	return options
}

func (s *Server) storageUserID(cfg *config.Config, info stateInfo) string {
	if cfg.Server.Secrets.Mode == "kubernetes" {
		return info.User
	}
	cred, ok := config.CredentialByID(cfg, info.CredentialID)
	if ok {
		return config.CredentialUserID(cfg, cred)
	}
	return info.CredentialID
}

func (s *Server) namespaceStorageID(cfg *config.Config, namespace, credentialID string) string {
	if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(namespace) {
		return namespace
	}
	return credentialID
}

func (s *Server) googleCredential(cfg *config.Config, credentialID string) (config.CredentialConfig, bool) {
	cred, ok := config.CredentialByID(cfg, credentialID)
	if !ok || cred.Type != "google-oauth-refresh-token" {
		return config.CredentialConfig{}, false
	}
	return cred, true
}

func (s *Server) notionCredential(cfg *config.Config, credentialID string) (config.CredentialConfig, bool) {
	cred, ok := config.CredentialByID(cfg, credentialID)
	if !ok || cred.Type != "notion-oauth-refresh-token" {
		return config.CredentialConfig{}, false
	}
	return cred, true
}

func (s *Server) slackCredential(cfg *config.Config, credentialID string) (config.CredentialConfig, bool) {
	cred, ok := config.CredentialByID(cfg, credentialID)
	if !ok || cred.Type != "slack-oauth-access-token" {
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

func (s *Server) notionClientID(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_id"]); value != "" {
		return value, nil
	}
	notionCfg, ok := config.NotionOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.notionClientValue(ctx, notionCfg.ClientID, notionCfg.ClientIDSecretRef)
}

func (s *Server) notionClientSecret(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_secret"]); value != "" {
		return value, nil
	}
	notionCfg, ok := config.NotionOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.notionClientValue(ctx, notionCfg.ClientSecret, notionCfg.ClientSecretRef)
}

func (s *Server) notionClientPair(ctx context.Context, notionCfg config.NotionOAuthConfig) (string, string, error) {
	clientID, err := s.notionClientValue(ctx, notionCfg.ClientID, notionCfg.ClientIDSecretRef)
	if err != nil {
		return "", "", err
	}
	clientSecret, err := s.notionClientValue(ctx, notionCfg.ClientSecret, notionCfg.ClientSecretRef)
	if err != nil {
		return "", "", err
	}
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("notion namespace requires client id and client secret")
	}
	return clientID, clientSecret, nil
}

func (s *Server) slackClientID(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_id"]); value != "" {
		return value, nil
	}
	slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.slackClientValue(ctx, slackCfg.ClientID, slackCfg.ClientIDSecretRef)
}

func (s *Server) slackClientSecret(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_secret"]); value != "" {
		return value, nil
	}
	slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.slackClientValue(ctx, slackCfg.ClientSecret, slackCfg.ClientSecretRef)
}

func (s *Server) notionClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, s.secrets, secretRef)
}

func (s *Server) googleClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, s.secrets, secretRef)
}

func (s *Server) slackClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, s.secrets, secretRef)
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

func slackScope(cfg *config.Config, cred config.CredentialConfig) string {
	if cred.Params["scope"] != "" {
		return cred.Params["scope"]
	}
	slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID)
	if ok {
		return slackCfg.Scope
	}
	return ""
}

func slackUserScope(cfg *config.Config, cred config.CredentialConfig) string {
	if cred.Params["user_scope"] != "" {
		return cred.Params["user_scope"]
	}
	if cred.Params["userScope"] != "" {
		return cred.Params["userScope"]
	}
	slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID)
	if ok {
		return slackCfg.UserScope
	}
	return ""
}

func slackTokenType(cfg *config.Config, cred config.CredentialConfig) string {
	if tokenType := cred.Params["token_type"]; tokenType != "" {
		return tokenType
	}
	if tokenType := cred.Params["tokenType"]; tokenType != "" {
		return tokenType
	}
	slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID)
	if ok && slackCfg.TokenType != "" {
		return slackCfg.TokenType
	}
	if slackScope(cfg, cred) == "" && slackUserScope(cfg, cred) != "" {
		return "user"
	}
	return "bot"
}

func notionConfigVersion(notionCfg config.NotionOAuthConfig) string {
	if notionCfg.NotionVersion != "" {
		return notionCfg.NotionVersion
	}
	return notionVersion
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
  {{if or .GoogleOptions .NotionOptions .SlackOptions}}
    {{range .GoogleOptions}}
      <div class="item">
        <div><strong>{{.CredentialID}}</strong>{{if .User}} for user <code>{{.User}}</code>{{end}}</div>
        <p class="muted"><code>{{.Scope}}</code></p>
        <p class="muted">{{.Source}}</p>
        <a class="button" href="/oauth/google/start?credential={{.CredentialID}}{{if .User}}&amp;user={{.User}}{{end}}">Authorize with Google</a>
      </div>
    {{end}}
    {{range .NotionOptions}}
      <div class="item">
        <div><strong>{{.CredentialID}}</strong>{{if .User}} for user <code>{{.User}}</code>{{end}}</div>
        <p class="muted">{{.Source}}</p>
        <a class="button" href="/oauth/notion/start?credential={{.CredentialID}}{{if .User}}&amp;user={{.User}}{{end}}">Authorize with Notion</a>
      </div>
    {{end}}
    {{range .SlackOptions}}
      <div class="item">
        <div><strong>{{.CredentialID}}</strong>{{if .User}} for user <code>{{.User}}</code>{{end}}</div>
        <p class="muted">token: <code>{{.TokenType}}</code>{{if .Scope}} scope: <code>{{.Scope}}</code>{{end}}{{if .UserScope}} user_scope: <code>{{.UserScope}}</code>{{end}}</p>
        <p class="muted">{{.Source}}</p>
        <a class="button" href="/oauth/slack/start?credential={{.CredentialID}}{{if .User}}&amp;user={{.User}}{{end}}">Authorize with Slack</a>
      </div>
    {{end}}
  {{else}}
    <p class="muted">No OAuth client is configured.</p>
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
  <h1>{{.Provider}} OAuth Complete</h1>
  {{if .User}}<p>User: <code>{{.User}}</code></p>{{end}}
  <p>Credential: <code>{{.CredentialID}}</code></p>
  <textarea readonly>{{if .RefreshToken}}refresh_token: "{{.RefreshToken}}"{{else}}access_token: "{{.AccessToken}}"{{end}}</textarea>
  {{if .Stored}}<p>The token was stored in the configured scia secret store.</p>{{end}}
  <p>You can also copy this value into {{if .RefreshToken}}<code>params.refresh_token</code>{{else}}<code>params.access_token</code>{{end}}{{if .ExpiresIn}}. Access token expires in {{.ExpiresIn}} seconds{{end}}.</p>
</body>
</html>`))
