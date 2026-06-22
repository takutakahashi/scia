package oauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"sort"
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
const todoistAuthURL = "https://app.todoist.com/oauth/authorize"
const todoistTokenURL = "https://api.todoist.com/oauth/access_token"
const todoistRevokeURL = "https://api.todoist.com/api/v1/revoke"
const slackAuthURL = "https://slack.com/oauth/v2_user/authorize"
const slackTokenURL = "https://slack.com/api/oauth.v2.user.access"
const slackRefreshTokenURL = "https://slack.com/api/oauth.v2.access"
const slackRevokeURL = "https://slack.com/api/auth.revoke"
const githubAuthURL = "https://github.com/login/oauth/authorize"
const githubTokenURL = "https://github.com/login/oauth/access_token"
const githubRevokeURL = "https://api.github.com/applications"

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
	RedirectURI  string
	CreatedAt    time.Time
}

type signedStatePayload struct {
	Version      int    `json:"v"`
	Provider     string `json:"provider"`
	User         string `json:"user,omitempty"`
	CredentialID string `json:"credential_id"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	CreatedAt    int64  `json:"created_at"`
	Nonce        string `json:"nonce"`
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

type todoistOption struct {
	User         string
	CredentialID string
	Scope        string
	Source       string
}

type slackOption struct {
	User         string
	CredentialID string
	Scope        string
	Source       string
}

type githubOption struct {
	User         string
	CredentialID string
	Scope        string
	Source       string
}

type integrationsResponse struct {
	Integrations []frontendIntegration `json:"integrations"`
}

type frontendIntegration struct {
	ID                       string                     `json:"id"`
	Provider                 string                     `json:"provider"`
	Namespace                string                     `json:"namespace,omitempty"`
	CredentialID             string                     `json:"credential_id"`
	Name                     string                     `json:"name"`
	IconURL                  string                     `json:"icon_url,omitempty"`
	Description              string                     `json:"description,omitempty"`
	Released                 bool                       `json:"released"`
	Source                   string                     `json:"source"`
	StartURL                 string                     `json:"start_url"`
	AuthorizationURLEndpoint string                     `json:"authorization_url_endpoint"`
	Setup                    map[string]string          `json:"setup"`
	Scopes                   []frontendIntegrationScope `json:"scopes"`
}

type frontendIntegrationScope struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Desc      string `json:"desc,omitempty"`
	Group     string `json:"group,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	GroupDesc string `json:"group_desc,omitempty"`
	Enabled   bool   `json:"enabled"`
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
	mux.HandleFunc("/api/integrations", s.frontendIntegrations)
	mux.HandleFunc("/oauth/google/start", s.startGoogle)
	mux.HandleFunc("/oauth/google/callback", s.googleCallback)
	mux.HandleFunc("/oauth/notion/start", s.startNotion)
	mux.HandleFunc("/oauth/notion/callback", s.notionCallback)
	mux.HandleFunc("/oauth/todoist/start", s.startTodoist)
	mux.HandleFunc("/oauth/todoist/callback", s.todoistCallback)
	mux.HandleFunc("/oauth/slack/start", s.startSlack)
	mux.HandleFunc("/oauth/slack/callback", s.slackCallback)
	mux.HandleFunc("/oauth/github/start", s.startGitHub)
	mux.HandleFunc("/oauth/github/callback", s.githubCallback)
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
		GoogleOptions  []googleOption
		NotionOptions  []notionOption
		TodoistOptions []todoistOption
		SlackOptions   []slackOption
		GitHubOptions  []githubOption
	}{GoogleOptions: options, NotionOptions: s.notionOptions(s.store.Get()), TodoistOptions: s.todoistOptions(s.store.Get()), SlackOptions: s.slackOptions(s.store.Get()), GitHubOptions: s.githubOptions(s.store.Get())}
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

func (s *Server) frontendIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, integrationsResponse{Integrations: s.frontendIntegrationList(r, s.store.Get())})
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
	scope, err := oauthScopeFromRequest(cfg, cred.ID, "google", r.URL.Query().Get("scope"), googleScope(cfg, cred), "openid email profile")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = s.redirectURL(r)
	}
	state, err := s.createState(r.Context(), "google", stateInfo{User: userID, CredentialID: credentialID, RedirectURI: redirectURI})
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
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
	info, ok, err := s.consumeState(r.Context(), state, "google")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
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
	token, err := s.exchangeCode(r.Context(), r, cred, code, info.RedirectURI)
	if err != nil {
		s.logger.Error("google oauth code exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	storageID := s.storageUserID(cfg, info)
	if err := s.secrets.Put(r.Context(), storageID, s.storageTokenKey(cfg, storageID, info.CredentialID, "refresh_token"), token.RefreshToken); err != nil {
		s.logger.Error("failed to store google refresh token", "error", err, "credential", info.CredentialID, "user", info.User)
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		TokenKind    string
		TokenValue   string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "Google",
		User:         info.User,
		CredentialID: info.CredentialID,
		TokenKind:    "refresh_token",
		TokenValue:   token.RefreshToken,
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
	state, err := s.createState(r.Context(), "notion", stateInfo{User: userID, CredentialID: credentialID})
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
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
	info, ok, err := s.consumeState(r.Context(), state, "notion")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
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
	storageID := s.storageUserID(cfg, info)
	if err := s.secrets.Put(r.Context(), storageID, s.storageTokenKey(cfg, storageID, info.CredentialID, "refresh_token"), token.RefreshToken); err != nil {
		s.logger.Error("failed to store notion refresh token", "error", err, "credential", info.CredentialID, "user", info.User)
		http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
		return
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		TokenKind    string
		TokenValue   string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "Notion",
		User:         info.User,
		CredentialID: info.CredentialID,
		TokenKind:    "refresh_token",
		TokenValue:   token.RefreshToken,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
		Stored:       true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = callbackTemplate.Execute(w, data)
}

func (s *Server) startTodoist(w http.ResponseWriter, r *http.Request) {
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
	cred, ok := s.todoistCredential(cfg, credentialID)
	if !ok {
		http.Error(w, "unknown todoist credential", http.StatusBadRequest)
		return
	}
	clientID, err := s.todoistClientID(r.Context(), cfg, cred)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "credential is missing client_id", http.StatusBadRequest)
		return
	}
	scope, err := oauthScopeFromRequest(cfg, cred.ID, "todoist", r.URL.Query().Get("scope"), todoistScope(cfg, cred), "data:read")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state, err := s.createState(r.Context(), "todoist", stateInfo{User: userID, CredentialID: credentialID})
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	authURL := todoistAuthURL
	redirectURI := ""
	if todoistCfg, ok := config.TodoistOAuthConfigForCredential(cfg, cred.ID); ok && todoistCfg.AuthURL != "" {
		authURL = todoistCfg.AuthURL
		redirectURI = todoistCfg.RedirectURL
	} else if todoistCfg, ok := config.TodoistOAuthConfigForCredential(cfg, cred.ID); ok {
		redirectURI = todoistCfg.RedirectURL
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", state)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) todoistCallback(w http.ResponseWriter, r *http.Request) {
	if errText := r.URL.Query().Get("error"); errText != "" {
		http.Error(w, errText, http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	info, ok, err := s.consumeState(r.Context(), state, "todoist")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
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
	cred, ok := s.todoistCredential(cfg, info.CredentialID)
	if !ok {
		http.Error(w, "credential disappeared", http.StatusBadRequest)
		return
	}
	token, err := s.exchangeTodoistCode(r.Context(), cred, code)
	if err != nil {
		s.logger.Error("todoist oauth code exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	storageID := s.storageUserID(cfg, info)
	storedTokenKind := "refresh_token"
	storedTokenValue := token.RefreshToken
	if storedTokenValue == "" {
		storedTokenKind = "access_token"
		storedTokenValue = token.AccessToken
	}
	if storedTokenValue == "" {
		http.Error(w, "token response did not include refresh_token or access_token", http.StatusBadGateway)
		return
	}
	if err := s.secrets.Put(r.Context(), storageID, s.storageTokenKey(cfg, storageID, info.CredentialID, storedTokenKind), storedTokenValue); err != nil {
		s.logger.Error("failed to store todoist token", "error", err, "credential", info.CredentialID, "user", info.User, "token_kind", storedTokenKind)
		http.Error(w, "failed to store token", http.StatusInternalServerError)
		return
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		TokenKind    string
		TokenValue   string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "Todoist",
		User:         info.User,
		CredentialID: info.CredentialID,
		TokenKind:    storedTokenKind,
		TokenValue:   storedTokenValue,
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
	scope, err := oauthScopeFromRequest(cfg, cred.ID, "slack", r.URL.Query().Get("scope"), slackScope(cfg, cred), "users:read")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = slackRedirectURLForCredential(cfg, cred)
	}
	state, err := s.createState(r.Context(), "slack", stateInfo{User: userID, CredentialID: credentialID, RedirectURI: redirectURI})
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	authURL := slackAuthURL
	if slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID); ok && slackCfg.AuthURL != "" {
		authURL = slackCfg.AuthURL
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", state)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) slackCallback(w http.ResponseWriter, r *http.Request) {
	if errText := r.URL.Query().Get("error"); errText != "" {
		http.Error(w, errText, http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	info, ok, err := s.consumeState(r.Context(), state, "slack")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
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
	token, err := s.exchangeSlackCode(r.Context(), cred, code, info.RedirectURI)
	if err != nil {
		s.logger.Error("slack oauth code exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	storageID := s.storageUserID(cfg, info)
	storedTokenKind := "refresh_token"
	storedTokenValue := token.RefreshToken
	if storedTokenValue == "" {
		storedTokenKind = "access_token"
		storedTokenValue = token.AccessToken
	}
	if storedTokenValue == "" {
		http.Error(w, "token response did not include refresh_token or access_token", http.StatusBadGateway)
		return
	}
	if err := s.secrets.Put(r.Context(), storageID, s.storageTokenKey(cfg, storageID, info.CredentialID, storedTokenKind), storedTokenValue); err != nil {
		s.logger.Error("failed to store slack token", "error", err, "credential", info.CredentialID, "user", info.User, "token_kind", storedTokenKind)
		http.Error(w, "failed to store token", http.StatusInternalServerError)
		return
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		TokenKind    string
		TokenValue   string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "Slack",
		User:         info.User,
		CredentialID: info.CredentialID,
		TokenKind:    storedTokenKind,
		TokenValue:   storedTokenValue,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
		Stored:       true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = callbackTemplate.Execute(w, data)
}

func (s *Server) startGitHub(w http.ResponseWriter, r *http.Request) {
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
	cred, ok := s.githubCredential(cfg, credentialID)
	if !ok {
		http.Error(w, "unknown github credential", http.StatusBadRequest)
		return
	}
	clientID, err := s.githubClientID(r.Context(), cfg, cred)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "credential is missing client_id", http.StatusBadRequest)
		return
	}
	scope, err := oauthScopeFromRequest(cfg, cred.ID, "github", r.URL.Query().Get("scope"), githubScope(cfg, cred), "read:user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = githubRedirectURLForCredential(cfg, cred)
	}
	state, err := s.createState(r.Context(), "github", stateInfo{User: userID, CredentialID: credentialID, RedirectURI: redirectURI})
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	authURL := githubAuthURL
	if githubCfg, ok := config.GitHubOAuthConfigForCredential(cfg, cred.ID); ok && githubCfg.AuthURL != "" {
		authURL = githubCfg.AuthURL
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", state)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) githubCallback(w http.ResponseWriter, r *http.Request) {
	if errText := r.URL.Query().Get("error"); errText != "" {
		http.Error(w, errText, http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	info, ok, err := s.consumeState(r.Context(), state, "github")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
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
	cred, ok := s.githubCredential(cfg, info.CredentialID)
	if !ok {
		http.Error(w, "credential disappeared", http.StatusBadRequest)
		return
	}
	token, err := s.exchangeGitHubCode(r.Context(), cred, code, info.RedirectURI)
	if err != nil {
		s.logger.Error("github oauth code exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	storageID := s.storageUserID(cfg, info)
	storedTokenKind := "refresh_token"
	storedTokenValue := token.RefreshToken
	if storedTokenValue == "" {
		storedTokenKind = "access_token"
		storedTokenValue = token.AccessToken
	}
	if storedTokenValue == "" {
		http.Error(w, "token response did not include refresh_token or access_token", http.StatusBadGateway)
		return
	}
	if err := s.secrets.Put(r.Context(), storageID, s.storageTokenKey(cfg, storageID, info.CredentialID, storedTokenKind), storedTokenValue); err != nil {
		s.logger.Error("failed to store github token", "error", err, "credential", info.CredentialID, "user", info.User, "token_kind", storedTokenKind)
		http.Error(w, "failed to store token", http.StatusInternalServerError)
		return
	}
	data := struct {
		Provider     string
		User         string
		CredentialID string
		TokenKind    string
		TokenValue   string
		RefreshToken string
		AccessToken  string
		ExpiresIn    int64
		Stored       bool
	}{
		Provider:     "GitHub",
		User:         info.User,
		CredentialID: info.CredentialID,
		TokenKind:    storedTokenKind,
		TokenValue:   storedTokenValue,
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
		Stored:       true,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = callbackTemplate.Execute(w, data)
}

type tokenResponse struct {
	OK           *bool  `json:"ok"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (s *Server) exchangeCode(ctx context.Context, r *http.Request, cred config.CredentialConfig, code, redirectURI string) (tokenResponse, error) {
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
	if redirectURI == "" {
		redirectURI = s.redirectURL(r)
	}
	form.Set("redirect_uri", redirectURI)
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

func (s *Server) exchangeTodoistCode(ctx context.Context, cred config.CredentialConfig, code string) (tokenResponse, error) {
	cfg := s.store.Get()
	tokenURL := cred.Params["token_url"]
	todoistCfg, hasTodoistCfg := config.TodoistOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasTodoistCfg {
		tokenURL = todoistCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = todoistTokenURL
	}
	clientID, err := s.todoistClientID(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	clientSecret, err := s.todoistClientSecret(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	if redirectURI := todoistRedirectURLForCredential(cfg, cred); redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
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
	if token.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("todoist did not return an access_token")
	}
	return token, nil
}

func (s *Server) exchangeSlackCode(ctx context.Context, cred config.CredentialConfig, code, redirectURI string) (tokenResponse, error) {
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
		return tokenResponse{}, err
	}
	clientSecret, err := s.slackClientSecret(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	if redirectURI == "" {
		redirectURI = slackRedirectURLForCredential(cfg, cred)
	}
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
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
	if token.OK != nil && !*token.OK {
		return tokenResponse{}, fmt.Errorf("%s: %s", token.Error, token.ErrorDesc)
	}
	if token.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("slack did not return an access_token")
	}
	return token, nil
}

func (s *Server) exchangeGitHubCode(ctx context.Context, cred config.CredentialConfig, code, redirectURI string) (tokenResponse, error) {
	cfg := s.store.Get()
	tokenURL := cred.Params["token_url"]
	githubCfg, hasGitHubCfg := config.GitHubOAuthConfigForCredential(cfg, cred.ID)
	if tokenURL == "" && hasGitHubCfg {
		tokenURL = githubCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = githubTokenURL
	}
	clientID, err := s.githubClientID(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	clientSecret, err := s.githubClientSecret(ctx, cfg, cred)
	if err != nil {
		return tokenResponse{}, err
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	if redirectURI == "" {
		redirectURI = githubRedirectURLForCredential(cfg, cred)
	}
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	if token.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("github did not return an access_token")
	}
	return token, nil
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
	case "todoist":
		if redirect := cfg.Server.OAuth.Todoist.RedirectURL; redirect != "" {
			return redirect
		}
	case "slack":
		if redirect := cfg.Server.OAuth.Slack.RedirectURL; redirect != "" {
			return redirect
		}
	case "github":
		if redirect := cfg.Server.OAuth.GitHub.RedirectURL; redirect != "" {
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
	case "todoist":
		credentialID := config.NamespaceTodoistCredentialID(namespace)
		todoistCfg, ok := config.TodoistOAuthConfigForCredential(cfg, credentialID)
		if !ok {
			http.Error(w, "unknown todoist namespace", http.StatusNotFound)
			return
		}
		s.namespaceTodoistOAuth(w, r, namespace, credentialID, action, todoistCfg)
	case "slack":
		credentialID := config.NamespaceSlackCredentialID(namespace)
		slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, credentialID)
		if !ok {
			http.Error(w, "unknown slack namespace", http.StatusNotFound)
			return
		}
		s.namespaceSlackOAuth(w, r, namespace, credentialID, action, slackCfg)
	case "github":
		credentialID := config.NamespaceGitHubCredentialID(namespace)
		githubCfg, ok := config.GitHubOAuthConfigForCredential(cfg, credentialID)
		if !ok {
			http.Error(w, "unknown github namespace", http.StatusNotFound)
			return
		}
		s.namespaceGitHubOAuth(w, r, namespace, credentialID, action, githubCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceGoogleOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, googleCfg config.GoogleOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
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
		s.namespaceGoogleRevoke(w, r, namespace, credentialID, googleCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceNotionOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, notionCfg config.NotionOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
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
		s.namespaceNotionRevoke(w, r, namespace, credentialID, notionCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceTodoistOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, todoistCfg config.TodoistOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceTodoistAuthorizationURL(w, r, namespace, credentialID, todoistCfg, false)
	case "start":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceTodoistAuthorizationURL(w, r, namespace, credentialID, todoistCfg, true)
	case "token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceTodoistToken(w, r, todoistCfg)
	case "access-token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceTodoistAccessToken(w, r, namespace, credentialID, todoistCfg)
	case "revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceTodoistRevoke(w, r, namespace, credentialID, todoistCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceSlackOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, slackCfg config.SlackOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
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
		s.namespaceSlackAccessToken(w, r, namespace, credentialID, slackCfg)
	case "revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceSlackRevoke(w, r, namespace, credentialID, slackCfg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) namespaceGitHubOAuth(w http.ResponseWriter, r *http.Request, namespace, credentialID, action string, githubCfg config.GitHubOAuthConfig) {
	switch action {
	case "authorization-url":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGitHubAuthorizationURL(w, r, namespace, credentialID, githubCfg, false)
	case "start":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGitHubAuthorizationURL(w, r, namespace, credentialID, githubCfg, true)
	case "token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGitHubToken(w, r, githubCfg)
	case "access-token":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGitHubAccessToken(w, r, namespace, credentialID, githubCfg)
	case "revoke":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.namespaceGitHubRevoke(w, r, namespace, credentialID, githubCfg)
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

type authorizationURLRequest struct {
	RedirectURI string   `json:"redirect_uri"`
	Scope       string   `json:"scope"`
	ScopeIDs    []string `json:"scope_ids"`
	State       string   `json:"state"`
	AccessType  string   `json:"access_type"`
	Prompt      string   `json:"prompt"`
}

func parseAuthorizationURLRequest(r *http.Request, provider string) (authorizationURLRequest, error) {
	if r.Method == http.MethodPost {
		var req authorizationURLRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			return authorizationURLRequest{}, fmt.Errorf("invalid json request: %w", err)
		}
		if len(req.ScopeIDs) > 0 {
			req.Scope = strings.Join(req.ScopeIDs, oauthScopeSeparator(provider))
		}
		return req, nil
	}
	query := r.URL.Query()
	return authorizationURLRequest{
		RedirectURI: query.Get("redirect_uri"),
		Scope:       query.Get("scope"),
		State:       query.Get("state"),
		AccessType:  query.Get("access_type"),
		Prompt:      query.Get("prompt"),
	}, nil
}

func (s *Server) namespaceGoogleAuthorizationURL(w http.ResponseWriter, r *http.Request, namespace, credentialID string, googleCfg config.GoogleOAuthConfig, redirect bool) {
	req, err := parseAuthorizationURLRequest(r, "google")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = googleCfg.RedirectURL
	}
	if redirectURI == "" {
		redirectURI = s.redirectURL(r)
	}
	scope, err := oauthScopeFromRequest(s.store.Get(), credentialID, "google", req.Scope, googleCfg.Scope, "openid email profile")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state := req.State
	if redirect || state == "" {
		generated, err := s.createState(r.Context(), "google", stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
			RedirectURI:  redirectURI,
		})
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
	q.Set("access_type", firstNonEmpty(req.AccessType, "offline"))
	q.Set("prompt", firstNonEmpty(req.Prompt, "consent"))
	if state != "" {
		q.Set("state", state)
	}
	location := authURL + "?" + q.Encode()
	if redirect {
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
	req, err := parseAuthorizationURLRequest(r, "notion")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = notionCfg.RedirectURL
	}
	if redirectURI == "" {
		redirectURI = s.providerRedirectURL(r, "notion")
	}
	state := req.State
	if redirect || state == "" {
		generated, err := s.createState(r.Context(), "notion", stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
		})
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

func (s *Server) namespaceTodoistAuthorizationURL(w http.ResponseWriter, r *http.Request, namespace, credentialID string, todoistCfg config.TodoistOAuthConfig, redirect bool) {
	req, err := parseAuthorizationURLRequest(r, "todoist")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientID, err := s.todoistClientValue(r.Context(), todoistCfg.ClientID, todoistCfg.ClientIDSecretRef)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "todoist namespace is missing client id", http.StatusBadRequest)
		return
	}
	authURL := todoistCfg.AuthURL
	if authURL == "" {
		authURL = todoistAuthURL
	}
	scope, err := oauthScopeFromRequest(s.store.Get(), credentialID, "todoist", req.Scope, todoistCfg.Scope, "data:read")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state := req.State
	if redirect || state == "" {
		generated, err := s.createState(r.Context(), "todoist", stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
		})
		if err != nil {
			http.Error(w, "failed to create state", http.StatusInternalServerError)
			return
		}
		state = generated
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = todoistCfg.RedirectURL
	}
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	q.Set("response_type", "code")
	q.Set("scope", scope)
	if state != "" {
		q.Set("state", state)
	}
	location := authURL + "?" + q.Encode()
	if redirect {
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

func (s *Server) namespaceSlackAuthorizationURL(w http.ResponseWriter, r *http.Request, namespace, credentialID string, slackCfg config.SlackOAuthConfig, redirect bool) {
	req, err := parseAuthorizationURLRequest(r, "slack")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
	scope, err := oauthScopeFromRequest(s.store.Get(), credentialID, "slack", req.Scope, slackCfg.Scope, "users:read")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state := req.State
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = slackCfg.RedirectURL
	}
	if redirect || state == "" {
		generated, err := s.createState(r.Context(), "slack", stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
			RedirectURI:  redirectURI,
		})
		if err != nil {
			http.Error(w, "failed to create state", http.StatusInternalServerError)
			return
		}
		state = generated
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	q.Set("response_type", "code")
	q.Set("scope", scope)
	if state != "" {
		q.Set("state", state)
	}
	location := authURL + "?" + q.Encode()
	if redirect {
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

func (s *Server) namespaceGitHubAuthorizationURL(w http.ResponseWriter, r *http.Request, namespace, credentialID string, githubCfg config.GitHubOAuthConfig, redirect bool) {
	req, err := parseAuthorizationURLRequest(r, "github")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientID, err := s.githubClientValue(r.Context(), githubCfg.ClientID, githubCfg.ClientIDSecretRef)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if clientID == "" {
		http.Error(w, "github namespace is missing client id", http.StatusBadRequest)
		return
	}
	authURL := githubCfg.AuthURL
	if authURL == "" {
		authURL = githubAuthURL
	}
	scope, err := oauthScopeFromRequest(s.store.Get(), credentialID, "github", req.Scope, githubCfg.Scope, "read:user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state := req.State
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = githubCfg.RedirectURL
	}
	if redirect || state == "" {
		generated, err := s.createState(r.Context(), "github", stateInfo{
			User:         s.namespaceStorageID(s.store.Get(), namespace, credentialID),
			CredentialID: credentialID,
			RedirectURI:  redirectURI,
		})
		if err != nil {
			http.Error(w, "failed to create state", http.StatusInternalServerError)
			return
		}
		state = generated
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	q.Set("response_type", "code")
	q.Set("scope", scope)
	if state != "" {
		q.Set("state", state)
	}
	location := authURL + "?" + q.Encode()
	if redirect {
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

func (s *Server) namespaceTodoistToken(w http.ResponseWriter, r *http.Request, todoistCfg config.TodoistOAuthConfig) {
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
	clientID, clientSecret, err := s.todoistClientPair(r.Context(), todoistCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstream := url.Values{}
	upstream.Set("client_id", clientID)
	upstream.Set("client_secret", clientSecret)
	if grantType == "refresh_token" {
		upstream.Set("grant_type", grantType)
		if form.Get("refresh_token") == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}
		upstream.Set("refresh_token", form.Get("refresh_token"))
		if scope := form.Get("scope"); scope != "" {
			upstream.Set("scope", scope)
		}
	} else {
		if form.Get("code") == "" {
			http.Error(w, "code is required", http.StatusBadRequest)
			return
		}
		upstream.Set("code", form.Get("code"))
		if redirectURI := form.Get("redirect_uri"); redirectURI != "" {
			upstream.Set("redirect_uri", redirectURI)
		} else if todoistCfg.RedirectURL != "" {
			upstream.Set("redirect_uri", todoistCfg.RedirectURL)
		}
	}
	tokenURL := todoistCfg.TokenURL
	if tokenURL == "" {
		tokenURL = todoistTokenURL
	}
	s.forwardForm(w, r, tokenURL, upstream)
}

func (s *Server) namespaceSlackToken(w http.ResponseWriter, r *http.Request, slackCfg config.SlackOAuthConfig) {
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
	clientID, clientSecret, err := s.slackClientPair(r.Context(), slackCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstream := url.Values{}
	upstream.Set("client_id", clientID)
	upstream.Set("client_secret", clientSecret)
	var tokenURL string
	if grantType == "refresh_token" {
		upstream.Set("grant_type", grantType)
		if form.Get("refresh_token") == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}
		upstream.Set("refresh_token", form.Get("refresh_token"))
		if scope := form.Get("scope"); scope != "" {
			upstream.Set("scope", scope)
		}
		tokenURL = slackCfg.RefreshTokenURL
		if tokenURL == "" {
			tokenURL = slackCfg.TokenURL
		}
		if tokenURL == "" {
			tokenURL = slackRefreshTokenURL
		}
	} else {
		if form.Get("code") == "" {
			http.Error(w, "code is required", http.StatusBadRequest)
			return
		}
		upstream.Set("code", form.Get("code"))
		if redirectURI := form.Get("redirect_uri"); redirectURI != "" {
			upstream.Set("redirect_uri", redirectURI)
		} else if slackCfg.RedirectURL != "" {
			upstream.Set("redirect_uri", slackCfg.RedirectURL)
		}
		tokenURL = slackCfg.TokenURL
		if tokenURL == "" {
			tokenURL = slackTokenURL
		}
	}
	s.forwardSlackForm(w, r, tokenURL, upstream, "", "")
}

func (s *Server) namespaceGitHubToken(w http.ResponseWriter, r *http.Request, githubCfg config.GitHubOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	grantType := form.Get("grant_type")
	if grantType == "" {
		grantType = "authorization_code"
	}
	if grantType != "refresh_token" && grantType != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, err := s.githubClientPair(r.Context(), githubCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upstream := url.Values{}
	upstream.Set("client_id", clientID)
	upstream.Set("client_secret", clientSecret)
	if grantType == "refresh_token" {
		upstream.Set("grant_type", grantType)
		if form.Get("refresh_token") == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}
		upstream.Set("refresh_token", form.Get("refresh_token"))
		if scope := form.Get("scope"); scope != "" {
			upstream.Set("scope", scope)
		}
	} else {
		if form.Get("code") == "" {
			http.Error(w, "code is required", http.StatusBadRequest)
			return
		}
		upstream.Set("code", form.Get("code"))
		if redirectURI := form.Get("redirect_uri"); redirectURI != "" {
			upstream.Set("redirect_uri", redirectURI)
		} else if githubCfg.RedirectURL != "" {
			upstream.Set("redirect_uri", githubCfg.RedirectURL)
		}
	}
	tokenURL := githubCfg.TokenURL
	if tokenURL == "" {
		tokenURL = githubTokenURL
	}
	s.forwardGitHubForm(w, r, tokenURL, upstream, "", "")
}

func (s *Server) namespaceGoogleAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string, googleCfg config.GoogleOAuthConfig) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	refreshToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "refresh_token")
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

func (s *Server) namespaceTodoistAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string, todoistCfg config.TodoistOAuthConfig) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	accessToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "access_token")
	if err != nil {
		s.logger.Error("failed to load todoist access token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load access token", http.StatusInternalServerError)
		return
	}
	if ok && accessToken != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   315360000,
		})
		return
	}
	refreshToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "refresh_token")
	if err != nil {
		s.logger.Error("failed to load todoist refresh token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load refresh token", http.StatusInternalServerError)
		return
	}
	if !ok || refreshToken == "" {
		http.Error(w, "refresh_token or access_token is not registered", http.StatusNotFound)
		return
	}
	clientID, clientSecret, err := s.todoistClientPair(r.Context(), todoistCfg)
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
	tokenURL := todoistCfg.TokenURL
	if tokenURL == "" {
		tokenURL = todoistTokenURL
	}
	s.forwardTodoistForm(w, r, tokenURL, upstream, storageID, s.storageTokenKey(cfg, storageID, credentialID, "refresh_token"))
}

func (s *Server) namespaceSlackAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string, slackCfg config.SlackOAuthConfig) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	accessToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "access_token")
	if err != nil {
		s.logger.Error("failed to load slack access token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load access token", http.StatusInternalServerError)
		return
	}
	if ok && accessToken != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   315360000,
		})
		return
	}
	refreshToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "refresh_token")
	if err != nil {
		s.logger.Error("failed to load slack refresh token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load refresh token", http.StatusInternalServerError)
		return
	}
	if !ok || refreshToken == "" {
		http.Error(w, "refresh_token or access_token is not registered", http.StatusNotFound)
		return
	}
	clientID, clientSecret, err := s.slackClientPair(r.Context(), slackCfg)
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
	tokenURL := slackCfg.RefreshTokenURL
	if tokenURL == "" {
		tokenURL = slackCfg.TokenURL
	}
	if tokenURL == "" {
		tokenURL = slackRefreshTokenURL
	}
	s.forwardSlackForm(w, r, tokenURL, upstream, storageID, s.storageTokenKey(cfg, storageID, credentialID, "refresh_token"))
}

func (s *Server) namespaceGitHubAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string, githubCfg config.GitHubOAuthConfig) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	accessToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "access_token")
	if err != nil {
		s.logger.Error("failed to load github access token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load access token", http.StatusInternalServerError)
		return
	}
	if ok && accessToken != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   315360000,
		})
		return
	}
	refreshToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "refresh_token")
	if err != nil {
		s.logger.Error("failed to load github refresh token", "error", err, "credential", credentialID, "storage", storageID)
		http.Error(w, "failed to load refresh token", http.StatusInternalServerError)
		return
	}
	if !ok || refreshToken == "" {
		http.Error(w, "refresh_token or access_token is not registered", http.StatusNotFound)
		return
	}
	clientID, clientSecret, err := s.githubClientPair(r.Context(), githubCfg)
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
	tokenURL := githubCfg.TokenURL
	if tokenURL == "" {
		tokenURL = githubTokenURL
	}
	s.forwardGitHubForm(w, r, tokenURL, upstream, storageID, s.storageTokenKey(cfg, storageID, credentialID, "refresh_token"))
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

func (s *Server) namespaceNotionAccessToken(w http.ResponseWriter, r *http.Request, namespace, credentialID string, notionCfg config.NotionOAuthConfig) {
	cfg := s.store.Get()
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	refreshToken, ok, err := s.getStoredToken(r.Context(), cfg, storageID, credentialID, "refresh_token")
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
	}, storageID, s.storageTokenKey(cfg, storageID, credentialID, "refresh_token"))
}

func (s *Server) namespaceGoogleRevoke(w http.ResponseWriter, r *http.Request, namespace, credentialID string, googleCfg config.GoogleOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if form.Get("token") == "" {
		s.disconnectNamespaceCredential(w, r, namespace, credentialID)
		return
	}
	revokeURL := googleCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = googleRevokeURL
	}
	upstream := url.Values{}
	upstream.Set("token", form.Get("token"))
	s.forwardFormAndDisconnect(w, r, revokeURL, upstream, namespace, credentialID)
}

func (s *Server) namespaceNotionRevoke(w http.ResponseWriter, r *http.Request, namespace, credentialID string, notionCfg config.NotionOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if form.Get("token") == "" {
		s.disconnectNamespaceCredential(w, r, namespace, credentialID)
		return
	}
	revokeURL := notionCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = notionRevokeURL
	}
	s.forwardNotionJSONAndDisconnect(w, r, revokeURL, notionCfg, map[string]string{"token": form.Get("token")}, namespace, credentialID)
}

func (s *Server) namespaceTodoistRevoke(w http.ResponseWriter, r *http.Request, namespace, credentialID string, todoistCfg config.TodoistOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := form.Get("token")
	if token == "" {
		token = form.Get("access_token")
	}
	if token == "" {
		s.disconnectNamespaceCredential(w, r, namespace, credentialID)
		return
	}
	clientID, clientSecret, err := s.todoistClientPair(r.Context(), todoistCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	revokeURL := todoistCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = todoistRevokeURL
	}
	s.forwardTodoistRevokeAndDisconnect(w, r, revokeURL, clientID, clientSecret, token, namespace, credentialID)
}

func (s *Server) namespaceSlackRevoke(w http.ResponseWriter, r *http.Request, namespace, credentialID string, slackCfg config.SlackOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := form.Get("token")
	if token == "" {
		token = form.Get("access_token")
	}
	if token == "" {
		s.disconnectNamespaceCredential(w, r, namespace, credentialID)
		return
	}
	revokeURL := slackCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = slackRevokeURL
	}
	upstream := url.Values{}
	upstream.Set("token", token)
	if test := form.Get("test"); test != "" {
		upstream.Set("test", test)
	}
	s.forwardFormAndDisconnect(w, r, revokeURL, upstream, namespace, credentialID)
}

func (s *Server) namespaceGitHubRevoke(w http.ResponseWriter, r *http.Request, namespace, credentialID string, githubCfg config.GitHubOAuthConfig) {
	form, err := parseFormOrJSON(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := form.Get("token")
	if token == "" {
		token = form.Get("access_token")
	}
	if token == "" {
		s.disconnectNamespaceCredential(w, r, namespace, credentialID)
		return
	}
	clientID, clientSecret, err := s.githubClientPair(r.Context(), githubCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	revokeURL := githubCfg.RevokeURL
	if revokeURL == "" {
		revokeURL = githubRevokeURL
	}
	endpoint := strings.TrimRight(revokeURL, "/") + "/" + url.PathEscape(clientID) + "/grant"
	s.forwardGitHubRevokeAndDisconnect(w, r, endpoint, clientID, clientSecret, token, namespace, credentialID)
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

func (s *Server) forwardFormAndDisconnect(w http.ResponseWriter, r *http.Request, endpoint string, form url.Values, namespace, credentialID string) {
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
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := s.deleteNamespaceCredentialTokens(r.Context(), s.store.Get(), namespace, credentialID); err != nil {
			s.logger.Error("failed to delete revoked token", "error", err, "namespace", namespace, "credential", credentialID)
			http.Error(w, "failed to delete stored token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) forwardTodoistForm(w http.ResponseWriter, r *http.Request, endpoint string, form url.Values, storageID, refreshTokenKey string) {
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
		if err := s.secrets.Put(r.Context(), storageID, firstNonEmpty(refreshTokenKey, "refresh_token"), token.RefreshToken); err != nil {
			s.logger.Error("failed to store rotated todoist refresh token", "error", err, "storage", storageID)
			http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = json.NewEncoder(w).Encode(token)
}

func (s *Server) forwardSlackForm(w http.ResponseWriter, r *http.Request, endpoint string, form url.Values, storageID, refreshTokenKey string) {
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		http.Error(w, "failed to decode upstream token response", http.StatusBadGateway)
		return
	}
	if token.OK != nil && !*token.OK {
		status := http.StatusBadGateway
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(token)
		return
	}
	if storageID != "" && token.RefreshToken != "" {
		if err := s.secrets.Put(r.Context(), storageID, firstNonEmpty(refreshTokenKey, "refresh_token"), token.RefreshToken); err != nil {
			s.logger.Error("failed to store rotated slack refresh token", "error", err, "storage", storageID)
			http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = json.NewEncoder(w).Encode(token)
}

func (s *Server) forwardGitHubForm(w http.ResponseWriter, r *http.Request, endpoint string, form url.Values, storageID, refreshTokenKey string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		http.Error(w, "failed to decode upstream token response", http.StatusBadGateway)
		return
	}
	if storageID != "" && token.RefreshToken != "" {
		if err := s.secrets.Put(r.Context(), storageID, firstNonEmpty(refreshTokenKey, "refresh_token"), token.RefreshToken); err != nil {
			s.logger.Error("failed to store rotated github refresh token", "error", err, "storage", storageID)
			http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = json.NewEncoder(w).Encode(token)
}

func (s *Server) forwardTodoistRevoke(w http.ResponseWriter, r *http.Request, endpoint, clientID, clientSecret, token string) {
	payload, err := json.Marshal(map[string]string{
		"token":           token,
		"token_type_hint": "access_token",
	})
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
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) forwardTodoistRevokeAndDisconnect(w http.ResponseWriter, r *http.Request, endpoint, clientID, clientSecret, token, namespace, credentialID string) {
	payload, err := json.Marshal(map[string]string{
		"token":           token,
		"token_type_hint": "access_token",
	})
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
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := s.deleteNamespaceCredentialTokens(r.Context(), s.store.Get(), namespace, credentialID); err != nil {
			s.logger.Error("failed to delete revoked token", "error", err, "namespace", namespace, "credential", credentialID)
			http.Error(w, "failed to delete stored token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) forwardGitHubRevoke(w http.ResponseWriter, r *http.Request, endpoint, clientID, clientSecret, token string) {
	payload, err := json.Marshal(map[string]string{"access_token": token})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, endpoint, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
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
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) forwardGitHubRevokeAndDisconnect(w http.ResponseWriter, r *http.Request, endpoint, clientID, clientSecret, token, namespace, credentialID string) {
	payload, err := json.Marshal(map[string]string{"access_token": token})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, endpoint, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
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
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := s.deleteNamespaceCredentialTokens(r.Context(), s.store.Get(), namespace, credentialID); err != nil {
			s.logger.Error("failed to delete revoked token", "error", err, "namespace", namespace, "credential", credentialID)
			http.Error(w, "failed to delete stored token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) forwardNotionJSON(w http.ResponseWriter, r *http.Request, endpoint string, notionCfg config.NotionOAuthConfig, body map[string]string, storageID string, refreshTokenKey ...string) {
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
		if err := s.secrets.Put(r.Context(), storageID, firstNonEmpty(append(refreshTokenKey, "refresh_token")...), token.RefreshToken); err != nil {
			s.logger.Error("failed to store rotated notion refresh token", "error", err, "storage", storageID)
			http.Error(w, "failed to store refresh token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = json.NewEncoder(w).Encode(token)
}

func (s *Server) forwardNotionJSONAndDisconnect(w http.ResponseWriter, r *http.Request, endpoint string, notionCfg config.NotionOAuthConfig, body map[string]string, namespace, credentialID string) {
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
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := s.deleteNamespaceCredentialTokens(r.Context(), s.store.Get(), namespace, credentialID); err != nil {
			s.logger.Error("failed to delete revoked token", "error", err, "namespace", namespace, "credential", credentialID)
			http.Error(w, "failed to delete stored token", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) frontendIntegrationList(r *http.Request, cfg *config.Config) []frontendIntegration {
	var integrations []frontendIntegration
	for _, option := range s.googleOptions(cfg) {
		integrations = append(integrations, s.googleFrontendIntegration(r, cfg, option))
	}
	for _, option := range s.notionOptions(cfg) {
		integrations = append(integrations, s.notionFrontendIntegration(r, cfg, option))
	}
	for _, option := range s.todoistOptions(cfg) {
		integrations = append(integrations, s.todoistFrontendIntegration(r, cfg, option))
	}
	for _, option := range s.slackOptions(cfg) {
		integrations = append(integrations, s.slackFrontendIntegration(r, cfg, option))
	}
	for _, option := range s.githubOptions(cfg) {
		integrations = append(integrations, s.githubFrontendIntegration(r, cfg, option))
	}
	sort.SliceStable(integrations, func(i, j int) bool {
		return integrations[i].ID < integrations[j].ID
	})
	return integrations
}

func (s *Server) googleFrontendIntegration(r *http.Request, cfg *config.Config, option googleOption) frontendIntegration {
	metadata := oauthIntegrationMetadata(cfg, option.CredentialID, "google")
	googleCfg, _ := config.GoogleOAuthConfigForCredential(cfg, option.CredentialID)
	cred, _ := config.CredentialByID(cfg, option.CredentialID)
	scope := option.Scope
	if scope == "" {
		scope = "openid email profile"
	}
	authURL := firstNonEmpty(cred.Params["auth_url"], googleCfg.AuthURL)
	if authURL == "" {
		authURL = googleAuthURL
	}
	tokenURL := firstNonEmpty(cred.Params["token_url"], googleCfg.TokenURL)
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	revokeURL := firstNonEmpty(cred.Params["revoke_url"], googleCfg.RevokeURL)
	if revokeURL == "" {
		revokeURL = googleRevokeURL
	}
	callbackURL := firstNonEmpty(cred.Params["redirect_uri"], googleCfg.RedirectURL)
	if callbackURL == "" {
		callbackURL = s.redirectURL(r)
	}
	return s.frontendIntegration(metadata, "google", option.CredentialID, option.Source, scope, callbackURL, authURL, tokenURL, revokeURL)
}

func (s *Server) notionFrontendIntegration(r *http.Request, cfg *config.Config, option notionOption) frontendIntegration {
	metadata := oauthIntegrationMetadata(cfg, option.CredentialID, "notion")
	notionCfg, _ := config.NotionOAuthConfigForCredential(cfg, option.CredentialID)
	cred, _ := config.CredentialByID(cfg, option.CredentialID)
	authURL := firstNonEmpty(cred.Params["auth_url"], notionCfg.AuthURL)
	if authURL == "" {
		authURL = notionAuthURL
	}
	tokenURL := firstNonEmpty(cred.Params["token_url"], notionCfg.TokenURL)
	if tokenURL == "" {
		tokenURL = notionTokenURL
	}
	revokeURL := firstNonEmpty(cred.Params["revoke_url"], notionCfg.RevokeURL)
	if revokeURL == "" {
		revokeURL = notionRevokeURL
	}
	callbackURL := firstNonEmpty(cred.Params["redirect_uri"], notionCfg.RedirectURL)
	if callbackURL == "" {
		callbackURL = s.providerRedirectURL(r, "notion")
	}
	return s.frontendIntegration(metadata, "notion", option.CredentialID, option.Source, "", callbackURL, authURL, tokenURL, revokeURL)
}

func (s *Server) todoistFrontendIntegration(_ *http.Request, cfg *config.Config, option todoistOption) frontendIntegration {
	metadata := oauthIntegrationMetadata(cfg, option.CredentialID, "todoist")
	todoistCfg, _ := config.TodoistOAuthConfigForCredential(cfg, option.CredentialID)
	cred, _ := config.CredentialByID(cfg, option.CredentialID)
	scope := option.Scope
	if scope == "" {
		scope = "data:read"
	}
	authURL := firstNonEmpty(cred.Params["auth_url"], todoistCfg.AuthURL)
	if authURL == "" {
		authURL = todoistAuthURL
	}
	tokenURL := firstNonEmpty(cred.Params["token_url"], todoistCfg.TokenURL)
	if tokenURL == "" {
		tokenURL = todoistTokenURL
	}
	revokeURL := firstNonEmpty(cred.Params["revoke_url"], todoistCfg.RevokeURL)
	if revokeURL == "" {
		revokeURL = todoistRevokeURL
	}
	return s.frontendIntegration(metadata, "todoist", option.CredentialID, option.Source, scope, firstNonEmpty(cred.Params["redirect_uri"], todoistCfg.RedirectURL), authURL, tokenURL, revokeURL)
}

func (s *Server) slackFrontendIntegration(_ *http.Request, cfg *config.Config, option slackOption) frontendIntegration {
	metadata := oauthIntegrationMetadata(cfg, option.CredentialID, "slack")
	slackCfg, _ := config.SlackOAuthConfigForCredential(cfg, option.CredentialID)
	cred, _ := config.CredentialByID(cfg, option.CredentialID)
	scope := option.Scope
	if scope == "" {
		scope = "users:read"
	}
	authURL := firstNonEmpty(cred.Params["auth_url"], slackCfg.AuthURL)
	if authURL == "" {
		authURL = slackAuthURL
	}
	tokenURL := firstNonEmpty(cred.Params["token_url"], slackCfg.TokenURL)
	if tokenURL == "" {
		tokenURL = slackTokenURL
	}
	revokeURL := firstNonEmpty(cred.Params["revoke_url"], slackCfg.RevokeURL)
	if revokeURL == "" {
		revokeURL = slackRevokeURL
	}
	return s.frontendIntegration(metadata, "slack", option.CredentialID, option.Source, scope, firstNonEmpty(cred.Params["redirect_uri"], slackCfg.RedirectURL), authURL, tokenURL, revokeURL)
}

func (s *Server) githubFrontendIntegration(_ *http.Request, cfg *config.Config, option githubOption) frontendIntegration {
	metadata := oauthIntegrationMetadata(cfg, option.CredentialID, "github")
	githubCfg, _ := config.GitHubOAuthConfigForCredential(cfg, option.CredentialID)
	cred, _ := config.CredentialByID(cfg, option.CredentialID)
	scope := option.Scope
	if scope == "" {
		scope = "read:user"
	}
	authURL := firstNonEmpty(cred.Params["auth_url"], githubCfg.AuthURL)
	if authURL == "" {
		authURL = githubAuthURL
	}
	tokenURL := firstNonEmpty(cred.Params["token_url"], githubCfg.TokenURL)
	if tokenURL == "" {
		tokenURL = githubTokenURL
	}
	revokeURL := firstNonEmpty(cred.Params["revoke_url"], githubCfg.RevokeURL)
	if revokeURL == "" {
		revokeURL = githubRevokeURL
	}
	return s.frontendIntegration(metadata, "github", option.CredentialID, option.Source, scope, firstNonEmpty(cred.Params["redirect_uri"], githubCfg.RedirectURL), authURL, tokenURL, revokeURL)
}

func (s *Server) frontendIntegration(metadata config.OAuthIntegrationMetadataConfig, provider, credentialID, source, configuredScope, callbackURL, authURL, tokenURL, revokeURL string) frontendIntegration {
	namespace := ""
	if strings.HasPrefix(source, "server.oauth.namespaces.") {
		namespace, _, _ = strings.Cut(strings.TrimPrefix(source, "server.oauth.namespaces."), ".")
	}
	setup := map[string]string{
		"callback_url": callbackURL,
		"auth_url":     authURL,
		"token_url":    tokenURL,
		"revoke_url":   revokeURL,
	}
	for key, value := range metadata.Setup {
		setup[key] = value
	}
	startURL := "/oauth/" + provider + "/start?credential=" + url.QueryEscape(credentialID)
	authorizationEndpoint := ""
	if namespace != "" {
		startURL = "/oauth/" + namespace + "/" + provider + "/start"
		authorizationEndpoint = "/oauth/" + namespace + "/" + provider + "/authorization-url"
	}
	return frontendIntegration{
		ID:                       credentialID,
		Provider:                 provider,
		Namespace:                namespace,
		CredentialID:             credentialID,
		Name:                     integrationName(metadata, provider),
		IconURL:                  metadata.IconURL,
		Description:              metadata.Description,
		Released:                 integrationReleased(metadata),
		Source:                   source,
		StartURL:                 startURL,
		AuthorizationURLEndpoint: authorizationEndpoint,
		Setup:                    setup,
		Scopes:                   integrationScopes(metadata, configuredScope),
	}
}

func oauthIntegrationMetadata(cfg *config.Config, id, provider string) config.OAuthIntegrationMetadataConfig {
	if cfg.Server.OAuth.Integrations != nil {
		if metadata, ok := cfg.Server.OAuth.Integrations[id]; ok {
			return metadata
		}
		if metadata, ok := cfg.Server.OAuth.Integrations[provider]; ok {
			return metadata
		}
	}
	return config.OAuthIntegrationMetadataConfig{}
}

func integrationName(metadata config.OAuthIntegrationMetadataConfig, provider string) string {
	if metadata.Name != "" {
		return metadata.Name
	}
	switch provider {
	case "google":
		return "Google"
	case "notion":
		return "Notion"
	case "todoist":
		return "Todoist"
	case "slack":
		return "Slack"
	case "github":
		return "GitHub"
	default:
		return provider
	}
}

func integrationReleased(metadata config.OAuthIntegrationMetadataConfig) bool {
	if metadata.Released == nil {
		return true
	}
	return *metadata.Released
}

func integrationScopes(metadata config.OAuthIntegrationMetadataConfig, configured string) []frontendIntegrationScope {
	configuredScopes := splitScopeValues(configured)
	enabledByValue := make(map[string]struct{}, len(configuredScopes))
	for _, scope := range configuredScopes {
		enabledByValue[scope] = struct{}{}
	}
	if len(metadata.Scopes) > 0 {
		scopes := make([]frontendIntegrationScope, 0, len(metadata.Scopes))
		for i, scope := range metadata.Scopes {
			if scope.Value == "" {
				continue
			}
			enabled := false
			if scope.Enabled != nil {
				enabled = *scope.Enabled
			} else if _, ok := enabledByValue[scope.Value]; ok {
				enabled = true
			}
			scopes = append(scopes, frontendIntegrationScope{
				ID:        integrationScopeID(scope, i),
				Name:      integrationScopeName(scope, i),
				Desc:      firstNonEmpty(scope.Desc, scope.Description),
				Group:     scope.Group,
				GroupName: scope.GroupName,
				GroupDesc: scope.GroupDesc,
				Enabled:   enabled,
			})
		}
		return scopes
	}
	scopes := make([]frontendIntegrationScope, 0, len(configuredScopes))
	for i := range configuredScopes {
		scopes = append(scopes, frontendIntegrationScope{
			ID:      fmt.Sprintf("scope-%d", i+1),
			Name:    fmt.Sprintf("Scope %d", i+1),
			Enabled: true,
		})
	}
	return scopes
}

func oauthScopeFromRequest(cfg *config.Config, credentialID, provider, requested, configured, fallback string) (string, error) {
	metadata := oauthIntegrationMetadata(cfg, credentialID, provider)
	if len(metadata.Scopes) == 0 {
		if requested != "" {
			return requested, nil
		}
		if configured != "" {
			return configured, nil
		}
		return fallback, nil
	}

	type allowedScope struct {
		value string
		group string
	}
	allowed := make(map[string]allowedScope, len(metadata.Scopes)*2)
	var selected []string
	selectedGroups := map[string]string{}
	for i, scope := range metadata.Scopes {
		if scope.Value == "" {
			continue
		}
		allowedValue := allowedScope{value: scope.Value, group: scope.Group}
		allowed[integrationScopeID(scope, i)] = allowedValue
		allowed[scope.Value] = allowedValue
		if requested == "" && scopeDefaultEnabled(scope, configured) {
			if err := selectOAuthScopeGroup(selectedGroups, allowedValue.value, allowedValue.group); err != nil {
				return "", err
			}
			selected = append(selected, scope.Value)
		}
	}
	if requested != "" {
		requestedScopes := splitScopeValues(requested)
		if len(requestedScopes) == 0 {
			return "", fmt.Errorf("scope must include at least one value")
		}
		selected = make([]string, 0, len(requestedScopes))
		for _, scope := range requestedScopes {
			allowedValue, ok := allowed[scope]
			if !ok {
				return "", fmt.Errorf("scope %q is not allowed for %s", scope, credentialID)
			}
			if err := selectOAuthScopeGroup(selectedGroups, allowedValue.value, allowedValue.group); err != nil {
				return "", err
			}
			selected = append(selected, allowedValue.value)
		}
	}
	if len(selected) == 0 {
		return "", fmt.Errorf("no scopes are enabled for %s", credentialID)
	}
	return strings.Join(selected, oauthScopeSeparator(provider)), nil
}

func selectOAuthScopeGroup(selectedGroups map[string]string, value, group string) error {
	if group == "" {
		return nil
	}
	if selected, ok := selectedGroups[group]; ok && selected != value {
		return fmt.Errorf("scope group %q can include only one selected scope", group)
	}
	selectedGroups[group] = value
	return nil
}

func integrationScopeID(scope config.OAuthIntegrationScopeConfig, index int) string {
	if scope.ID != "" {
		return scope.ID
	}
	if name := firstNonEmpty(scope.Name, scope.Label, scope.ID); name != "" {
		if id := slugifyScopeID(name); id != "" {
			return id
		}
	}
	return fmt.Sprintf("scope-%d", index+1)
}

func integrationScopeName(scope config.OAuthIntegrationScopeConfig, index int) string {
	return firstNonEmpty(scope.Name, scope.Label, scope.ID, fmt.Sprintf("Scope %d", index+1))
}

func slugifyScopeID(value string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func scopeDefaultEnabled(scope config.OAuthIntegrationScopeConfig, configured string) bool {
	if scope.Enabled != nil {
		return *scope.Enabled
	}
	for _, configuredScope := range splitScopeValues(configured) {
		if configuredScope == scope.Value {
			return true
		}
	}
	return false
}

func oauthScopeSeparator(provider string) string {
	if provider == "todoist" {
		return ","
	}
	return " "
}

func splitScopeValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var scopes []string
	for _, scope := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	}) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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

func (s *Server) todoistOptions(cfg *config.Config) []todoistOption {
	var options []todoistOption
	appendOption := func(userID, credentialID, scope, source string) {
		options = append(options, todoistOption{
			User:         userID,
			CredentialID: credentialID,
			Scope:        scope,
			Source:       source,
		})
	}
	configID := cfg.TodoistOAuthCredentialID()
	hasConfigClient := cfg.Server.OAuth.Todoist.HasClientConfig()
	hasExplicitConfigCredential := false
	for _, cred := range cfg.Credentials {
		if cred.Type == "todoist-oauth-refresh-token" && cred.ID == configID {
			hasExplicitConfigCredential = true
			break
		}
	}
	if hasConfigClient && !hasExplicitConfigCredential {
		if cfg.Server.Secrets.Mode == "kubernetes" {
			for userID := range cfg.Server.Users {
				appendOption(userID, configID, todoistScope(cfg, config.CredentialConfig{}), "server.oauth.todoist")
			}
		} else {
			appendOption("", configID, todoistScope(cfg, config.CredentialConfig{}), "server.oauth.todoist")
		}
	}
	for _, cred := range cfg.Credentials {
		if cred.Type == "todoist-oauth-refresh-token" {
			userID := config.CredentialUserID(cfg, cred)
			if cfg.Server.Secrets.Mode == "kubernetes" && userID == cred.ID {
				for configuredUserID := range cfg.Server.Users {
					appendOption(configuredUserID, cred.ID, todoistScope(cfg, cred), "credentials")
				}
				continue
			}
			appendOption(userID, cred.ID, todoistScope(cfg, cred), "credentials")
		}
	}
	for namespace, ns := range cfg.Server.OAuth.Namespaces {
		if ns.Todoist.HasClientConfig() {
			credentialID := config.NamespaceTodoistCredentialID(namespace)
			if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(namespace) {
				appendOption(namespace, credentialID, ns.Todoist.Scope, "server.oauth.namespaces."+namespace+".todoist")
			} else if cfg.Server.Secrets.Mode != "kubernetes" {
				appendOption("", credentialID, ns.Todoist.Scope, "server.oauth.namespaces."+namespace+".todoist")
			}
		}
	}
	return options
}

func (s *Server) slackOptions(cfg *config.Config) []slackOption {
	var options []slackOption
	appendOption := func(userID, credentialID, scope, source string) {
		options = append(options, slackOption{
			User:         userID,
			CredentialID: credentialID,
			Scope:        scope,
			Source:       source,
		})
	}
	configID := cfg.SlackOAuthCredentialID()
	hasConfigClient := cfg.Server.OAuth.Slack.HasClientConfig()
	hasExplicitConfigCredential := false
	for _, cred := range cfg.Credentials {
		if cred.Type == "slack-user-oauth-token" && cred.ID == configID {
			hasExplicitConfigCredential = true
			break
		}
	}
	if hasConfigClient && !hasExplicitConfigCredential {
		if cfg.Server.Secrets.Mode == "kubernetes" {
			for userID := range cfg.Server.Users {
				appendOption(userID, configID, slackScope(cfg, config.CredentialConfig{}), "server.oauth.slack")
			}
		} else {
			appendOption("", configID, slackScope(cfg, config.CredentialConfig{}), "server.oauth.slack")
		}
	}
	for _, cred := range cfg.Credentials {
		if cred.Type == "slack-user-oauth-token" {
			userID := config.CredentialUserID(cfg, cred)
			if cfg.Server.Secrets.Mode == "kubernetes" && userID == cred.ID {
				for configuredUserID := range cfg.Server.Users {
					appendOption(configuredUserID, cred.ID, slackScope(cfg, cred), "credentials")
				}
				continue
			}
			appendOption(userID, cred.ID, slackScope(cfg, cred), "credentials")
		}
	}
	for namespace, ns := range cfg.Server.OAuth.Namespaces {
		if ns.Slack.HasClientConfig() {
			credentialID := config.NamespaceSlackCredentialID(namespace)
			if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(namespace) {
				appendOption(namespace, credentialID, ns.Slack.Scope, "server.oauth.namespaces."+namespace+".slack")
			} else if cfg.Server.Secrets.Mode != "kubernetes" {
				appendOption("", credentialID, ns.Slack.Scope, "server.oauth.namespaces."+namespace+".slack")
			}
		}
	}
	return options
}

func (s *Server) githubOptions(cfg *config.Config) []githubOption {
	var options []githubOption
	appendOption := func(userID, credentialID, scope, source string) {
		options = append(options, githubOption{
			User:         userID,
			CredentialID: credentialID,
			Scope:        scope,
			Source:       source,
		})
	}
	configID := cfg.GitHubOAuthCredentialID()
	hasConfigClient := cfg.Server.OAuth.GitHub.HasClientConfig()
	hasExplicitConfigCredential := false
	for _, cred := range cfg.Credentials {
		if cred.Type == "github-oauth-token" && cred.ID == configID {
			hasExplicitConfigCredential = true
			break
		}
	}
	if hasConfigClient && !hasExplicitConfigCredential {
		if cfg.Server.Secrets.Mode == "kubernetes" {
			for userID := range cfg.Server.Users {
				appendOption(userID, configID, githubScope(cfg, config.CredentialConfig{}), "server.oauth.github")
			}
		} else {
			appendOption("", configID, githubScope(cfg, config.CredentialConfig{}), "server.oauth.github")
		}
	}
	for _, cred := range cfg.Credentials {
		if cred.Type == "github-oauth-token" {
			userID := config.CredentialUserID(cfg, cred)
			if cfg.Server.Secrets.Mode == "kubernetes" && userID == cred.ID {
				for configuredUserID := range cfg.Server.Users {
					appendOption(configuredUserID, cred.ID, githubScope(cfg, cred), "credentials")
				}
				continue
			}
			appendOption(userID, cred.ID, githubScope(cfg, cred), "credentials")
		}
	}
	for namespace, ns := range cfg.Server.OAuth.Namespaces {
		if ns.GitHub.HasClientConfig() {
			credentialID := config.NamespaceGitHubCredentialID(namespace)
			if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(namespace) {
				appendOption(namespace, credentialID, ns.GitHub.Scope, "server.oauth.namespaces."+namespace+".github")
			} else if cfg.Server.Secrets.Mode != "kubernetes" {
				appendOption("", credentialID, ns.GitHub.Scope, "server.oauth.namespaces."+namespace+".github")
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

func (s *Server) storageTokenKey(cfg *config.Config, storageID, credentialID, key string) string {
	if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(storageID) && credentialID != "" {
		return credentialID + "." + key
	}
	return key
}

func (s *Server) getStoredToken(ctx context.Context, cfg *config.Config, storageID, credentialID, key string) (string, bool, error) {
	storageKey := s.storageTokenKey(cfg, storageID, credentialID, key)
	value, ok, err := s.secrets.Get(ctx, storageID, storageKey)
	if err != nil || ok || storageKey == key {
		return value, ok, err
	}
	if key == "refresh_token" && strings.HasSuffix(credentialID, ".google") {
		return s.secrets.Get(ctx, storageID, key)
	}
	return "", false, nil
}

func (s *Server) disconnectNamespaceCredential(w http.ResponseWriter, r *http.Request, namespace, credentialID string) {
	if err := s.deleteNamespaceCredentialTokens(r.Context(), s.store.Get(), namespace, credentialID); err != nil {
		s.logger.Error("failed to delete stored token", "error", err, "namespace", namespace, "credential", credentialID)
		http.Error(w, "failed to delete stored token", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revoked":       true,
		"credential_id": credentialID,
	})
}

func (s *Server) deleteNamespaceCredentialTokens(ctx context.Context, cfg *config.Config, namespace, credentialID string) error {
	storageID := s.namespaceStorageID(cfg, namespace, credentialID)
	for _, key := range []string{"refresh_token", "access_token"} {
		if err := s.secrets.Delete(ctx, storageID, s.storageTokenKey(cfg, storageID, credentialID, key)); err != nil {
			return err
		}
	}
	if cfg.Server.Secrets.Mode == "kubernetes" && cfg.HasUser(storageID) && strings.HasSuffix(credentialID, ".google") {
		if err := s.secrets.Delete(ctx, storageID, "refresh_token"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) createState(ctx context.Context, provider string, info stateInfo) (string, error) {
	if info.CreatedAt.IsZero() {
		info.CreatedAt = time.Now()
	}
	nonce, err := randomState()
	if err != nil {
		return "", err
	}
	payload := signedStatePayload{
		Version:      1,
		Provider:     provider,
		User:         info.User,
		CredentialID: info.CredentialID,
		RedirectURI:  info.RedirectURI,
		CreatedAt:    info.CreatedAt.Unix(),
		Nonce:        nonce,
	}
	key, err := s.stateSigningKey(ctx, s.store.Get(), provider, info.CredentialID)
	if err != nil {
		return "", err
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sig := signState(rawPayload, []byte(key))
	return base64.RawURLEncoding.EncodeToString(rawPayload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Server) consumeState(ctx context.Context, state, provider string) (stateInfo, bool, error) {
	if state == "" {
		return stateInfo{}, false, nil
	}
	parts := strings.Split(state, ".")
	if len(parts) == 2 {
		rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return stateInfo{}, false, nil
		}
		gotSig, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return stateInfo{}, false, nil
		}
		var payload signedStatePayload
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return stateInfo{}, false, nil
		}
		if payload.Version != 1 || payload.Provider != provider || payload.CredentialID == "" || payload.Nonce == "" {
			return stateInfo{}, false, nil
		}
		key, err := s.stateSigningKey(ctx, s.store.Get(), provider, payload.CredentialID)
		if err != nil {
			return stateInfo{}, false, err
		}
		if !hmac.Equal(gotSig, signState(rawPayload, []byte(key))) {
			return stateInfo{}, false, nil
		}
		return stateInfo{
			User:         payload.User,
			CredentialID: payload.CredentialID,
			RedirectURI:  payload.RedirectURI,
			CreatedAt:    time.Unix(payload.CreatedAt, 0),
		}, true, nil
	}

	rawInfo, ok := s.states.LoadAndDelete(state)
	if !ok {
		return stateInfo{}, false, nil
	}
	info, ok := rawInfo.(stateInfo)
	if !ok {
		return stateInfo{}, false, nil
	}
	return info, true, nil
}

func signState(payload, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func (s *Server) stateSigningKey(ctx context.Context, cfg *config.Config, provider, credentialID string) (string, error) {
	switch provider {
	case "google":
		cred, ok := s.googleCredential(cfg, credentialID)
		if !ok {
			return "", fmt.Errorf("unknown google credential")
		}
		secret, err := s.googleClientSecret(ctx, cfg, cred)
		if err != nil {
			return "", err
		}
		if secret == "" {
			return "", fmt.Errorf("google credential is missing client_secret")
		}
		return secret, nil
	case "notion":
		cred, ok := s.notionCredential(cfg, credentialID)
		if !ok {
			return "", fmt.Errorf("unknown notion credential")
		}
		secret, err := s.notionClientSecret(ctx, cfg, cred)
		if err != nil {
			return "", err
		}
		if secret == "" {
			return "", fmt.Errorf("notion credential is missing client_secret")
		}
		return secret, nil
	case "todoist":
		cred, ok := s.todoistCredential(cfg, credentialID)
		if !ok {
			return "", fmt.Errorf("unknown todoist credential")
		}
		secret, err := s.todoistClientSecret(ctx, cfg, cred)
		if err != nil {
			return "", err
		}
		if secret == "" {
			return "", fmt.Errorf("todoist credential is missing client_secret")
		}
		return secret, nil
	case "slack":
		cred, ok := s.slackCredential(cfg, credentialID)
		if !ok {
			return "", fmt.Errorf("unknown slack credential")
		}
		secret, err := s.slackClientSecret(ctx, cfg, cred)
		if err != nil {
			return "", err
		}
		if secret == "" {
			return "", fmt.Errorf("slack credential is missing client_secret")
		}
		return secret, nil
	case "github":
		cred, ok := s.githubCredential(cfg, credentialID)
		if !ok {
			return "", fmt.Errorf("unknown github credential")
		}
		secret, err := s.githubClientSecret(ctx, cfg, cred)
		if err != nil {
			return "", err
		}
		if secret == "" {
			return "", fmt.Errorf("github credential is missing client_secret")
		}
		return secret, nil
	default:
		return "", fmt.Errorf("unknown provider %q", provider)
	}
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

func (s *Server) todoistCredential(cfg *config.Config, credentialID string) (config.CredentialConfig, bool) {
	cred, ok := config.CredentialByID(cfg, credentialID)
	if !ok || cred.Type != "todoist-oauth-refresh-token" {
		return config.CredentialConfig{}, false
	}
	return cred, true
}

func (s *Server) slackCredential(cfg *config.Config, credentialID string) (config.CredentialConfig, bool) {
	cred, ok := config.CredentialByID(cfg, credentialID)
	if !ok || cred.Type != "slack-user-oauth-token" {
		return config.CredentialConfig{}, false
	}
	return cred, true
}

func (s *Server) githubCredential(cfg *config.Config, credentialID string) (config.CredentialConfig, bool) {
	cred, ok := config.CredentialByID(cfg, credentialID)
	if !ok || cred.Type != "github-oauth-token" {
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

func (s *Server) todoistClientID(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_id"]); value != "" {
		return value, nil
	}
	todoistCfg, ok := config.TodoistOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.todoistClientValue(ctx, todoistCfg.ClientID, todoistCfg.ClientIDSecretRef)
}

func (s *Server) todoistClientSecret(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_secret"]); value != "" {
		return value, nil
	}
	todoistCfg, ok := config.TodoistOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.todoistClientValue(ctx, todoistCfg.ClientSecret, todoistCfg.ClientSecretRef)
}

func (s *Server) todoistClientPair(ctx context.Context, todoistCfg config.TodoistOAuthConfig) (string, string, error) {
	clientID, err := s.todoistClientValue(ctx, todoistCfg.ClientID, todoistCfg.ClientIDSecretRef)
	if err != nil {
		return "", "", err
	}
	clientSecret, err := s.todoistClientValue(ctx, todoistCfg.ClientSecret, todoistCfg.ClientSecretRef)
	if err != nil {
		return "", "", err
	}
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("todoist namespace requires client id and client secret")
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

func (s *Server) slackClientPair(ctx context.Context, slackCfg config.SlackOAuthConfig) (string, string, error) {
	clientID, err := s.slackClientValue(ctx, slackCfg.ClientID, slackCfg.ClientIDSecretRef)
	if err != nil {
		return "", "", err
	}
	clientSecret, err := s.slackClientValue(ctx, slackCfg.ClientSecret, slackCfg.ClientSecretRef)
	if err != nil {
		return "", "", err
	}
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("slack namespace requires client id and client secret")
	}
	return clientID, clientSecret, nil
}

func (s *Server) githubClientID(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_id"]); value != "" {
		return value, nil
	}
	githubCfg, ok := config.GitHubOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.githubClientValue(ctx, githubCfg.ClientID, githubCfg.ClientIDSecretRef)
}

func (s *Server) githubClientSecret(ctx context.Context, cfg *config.Config, cred config.CredentialConfig) (string, error) {
	if value := config.HeaderValueFromEnv(cred.Params["client_secret"]); value != "" {
		return value, nil
	}
	githubCfg, ok := config.GitHubOAuthConfigForCredential(cfg, cred.ID)
	if !ok {
		return "", nil
	}
	return s.githubClientValue(ctx, githubCfg.ClientSecret, githubCfg.ClientSecretRef)
}

func (s *Server) githubClientPair(ctx context.Context, githubCfg config.GitHubOAuthConfig) (string, string, error) {
	clientID, err := s.githubClientValue(ctx, githubCfg.ClientID, githubCfg.ClientIDSecretRef)
	if err != nil {
		return "", "", err
	}
	clientSecret, err := s.githubClientValue(ctx, githubCfg.ClientSecret, githubCfg.ClientSecretRef)
	if err != nil {
		return "", "", err
	}
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("github namespace requires client id and client secret")
	}
	return clientID, clientSecret, nil
}

func (s *Server) todoistClientValue(ctx context.Context, literal, secretRef string) (string, error) {
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

func (s *Server) githubClientValue(ctx context.Context, literal, secretRef string) (string, error) {
	if value := config.HeaderValueFromEnv(literal); value != "" {
		return value, nil
	}
	if secretRef == "" {
		return "", nil
	}
	return secrets.ResolveRef(ctx, s.secrets, secretRef)
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

func todoistScope(cfg *config.Config, cred config.CredentialConfig) string {
	if cred.Params["scope"] != "" {
		return cred.Params["scope"]
	}
	todoistCfg, ok := config.TodoistOAuthConfigForCredential(cfg, cred.ID)
	if ok {
		return todoistCfg.Scope
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

func githubScope(cfg *config.Config, cred config.CredentialConfig) string {
	if cred.Params["scope"] != "" {
		return cred.Params["scope"]
	}
	githubCfg, ok := config.GitHubOAuthConfigForCredential(cfg, cred.ID)
	if ok {
		return githubCfg.Scope
	}
	return ""
}

func todoistRedirectURLForCredential(cfg *config.Config, cred config.CredentialConfig) string {
	if redirectURI := cred.Params["redirect_uri"]; redirectURI != "" {
		return redirectURI
	}
	if todoistCfg, ok := config.TodoistOAuthConfigForCredential(cfg, cred.ID); ok {
		return todoistCfg.RedirectURL
	}
	return ""
}

func slackRedirectURLForCredential(cfg *config.Config, cred config.CredentialConfig) string {
	if redirectURI := cred.Params["redirect_uri"]; redirectURI != "" {
		return redirectURI
	}
	if slackCfg, ok := config.SlackOAuthConfigForCredential(cfg, cred.ID); ok {
		return slackCfg.RedirectURL
	}
	return ""
}

func githubRedirectURLForCredential(cfg *config.Config, cred config.CredentialConfig) string {
	if redirectURI := cred.Params["redirect_uri"]; redirectURI != "" {
		return redirectURI
	}
	if githubCfg, ok := config.GitHubOAuthConfigForCredential(cfg, cred.ID); ok {
		return githubCfg.RedirectURL
	}
	return ""
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
  {{if or .GoogleOptions .NotionOptions .TodoistOptions .SlackOptions .GitHubOptions}}
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
    {{range .TodoistOptions}}
      <div class="item">
        <div><strong>{{.CredentialID}}</strong>{{if .User}} for user <code>{{.User}}</code>{{end}}</div>
        <p class="muted"><code>{{.Scope}}</code></p>
        <p class="muted">{{.Source}}</p>
        <a class="button" href="/oauth/todoist/start?credential={{.CredentialID}}{{if .User}}&amp;user={{.User}}{{end}}">Authorize with Todoist</a>
      </div>
    {{end}}
    {{range .SlackOptions}}
      <div class="item">
        <div><strong>{{.CredentialID}}</strong>{{if .User}} for user <code>{{.User}}</code>{{end}}</div>
        <p class="muted"><code>{{.Scope}}</code></p>
        <p class="muted">{{.Source}}</p>
        <a class="button" href="/oauth/slack/start?credential={{.CredentialID}}{{if .User}}&amp;user={{.User}}{{end}}">Authorize with Slack</a>
      </div>
    {{end}}
    {{range .GitHubOptions}}
      <div class="item">
        <div><strong>{{.CredentialID}}</strong>{{if .User}} for user <code>{{.User}}</code>{{end}}</div>
        <p class="muted"><code>{{.Scope}}</code></p>
        <p class="muted">{{.Source}}</p>
        <a class="button" href="/oauth/github/start?credential={{.CredentialID}}{{if .User}}&amp;user={{.User}}{{end}}">Authorize with GitHub</a>
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
  <textarea readonly>{{.TokenKind}}: "{{.TokenValue}}"</textarea>
  {{if .Stored}}<p>The token was stored in the configured scia secret store.</p>{{end}}
  <p>You can also copy this value into <code>params.{{.TokenKind}}</code>{{if .ExpiresIn}}. Access token expires in {{.ExpiresIn}} seconds{{end}}.</p>
</body>
</html>`))
