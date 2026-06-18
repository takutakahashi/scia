package secrets_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/takutakahashi/scia/internal/auth"
	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/oauth"
	"github.com/takutakahashi/scia/internal/secrets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestKubernetesOAuthCallbackAndProxyInjection(t *testing.T) {
	if os.Getenv("SCIA_K8S_INTEGRATION") != "1" {
		t.Skip("set SCIA_K8S_INTEGRATION=1 to run kubernetes integration tests")
	}

	env := &envtest.Environment{}
	restCfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		_ = env.Stop()
	})

	ctx := context.Background()
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "scia"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "callback-access-token",
				"refresh_token": "k8s-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "refresh_token":
			if r.Form.Get("refresh_token") != "k8s-refresh-token" {
				t.Fatalf("unexpected refresh token: %q", r.Form.Get("refresh_token"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "proxy-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			t.Fatalf("unexpected grant_type: %q", r.Form.Get("grant_type"))
		}
	}))
	defer tokenEndpoint.Close()

	secretStore, err := secrets.NewKubernetesStore(client, namespace, map[string]string{"alice": "scia-oauth-alice"})
	if err != nil {
		t.Fatal(err)
	}

	appCfg := &config.Config{
		Server: config.ServerConfig{
			Mode: "oauth",
			Secrets: config.SecretsConfig{
				Mode: "kubernetes",
				Kubernetes: config.KubernetesSecretsConfig{
					Namespace: namespace,
				},
			},
			Users: map[string]config.UserConfig{
				"alice": {SecretName: "scia-oauth-alice"},
			},
			OAuth: config.OAuthConfig{
				RedirectURL: "http://oauth.test/oauth/google/callback",
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
		Credentials: []config.CredentialConfig{
			{ID: "google-calendar", Type: "google-oauth-refresh-token"},
		},
	}
	if err := appCfg.Validate(); err != nil {
		t.Fatal(err)
	}

	store, err := config.NewStore(ctx, staticProvider{cfg: appCfg}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	oauthServer := oauth.NewServer(store, secretStore, slog.Default())

	startReq := httptest.NewRequest(http.MethodGet, "/oauth/google/start?credential=google-calendar&user=alice", nil)
	startRec := httptest.NewRecorder()
	oauthServer.Handler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusFound {
		t.Fatalf("start failed: status=%d body=%s", startRec.Code, startRec.Body.String())
	}
	redirectURL, err := url.Parse(startRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := redirectURL.Query().Get("state")
	if state == "" {
		t.Fatal("missing oauth state")
	}

	callbackReq := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state="+state+"&code=auth-code", nil)
	callbackRec := httptest.NewRecorder()
	oauthServer.Handler().ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusOK {
		t.Fatalf("callback failed: status=%d body=%s", callbackRec.Code, callbackRec.Body.String())
	}
	if !strings.Contains(callbackRec.Body.String(), "k8s-refresh-token") {
		t.Fatalf("callback page missing refresh token: %s", callbackRec.Body.String())
	}

	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, "scia-oauth-alice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["refresh_token"]) != "k8s-refresh-token" {
		t.Fatalf("unexpected refresh token in secret: %q", secret.Data["refresh_token"])
	}

	proxyCfg := &config.Config{
		Server: config.ServerConfig{
			Mode: "proxy",
			Secrets: config.SecretsConfig{
				Mode: "kubernetes",
				Kubernetes: config.KubernetesSecretsConfig{
					Namespace: namespace,
				},
			},
			Users: map[string]config.UserConfig{
				"alice": {SecretName: "scia-oauth-alice"},
			},
			OAuth: config.OAuthConfig{
				Google: config.GoogleOAuthConfig{
					CredentialID: "google-calendar",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					TokenURL:     tokenEndpoint.URL,
				},
			},
		},
		Credentials: []config.CredentialConfig{
			{
				ID:   "google-calendar",
				Type: "google-oauth-refresh-token",
				Params: map[string]string{
					"user": "alice",
				},
			},
		},
		Rules: []config.RuleConfig{
			{
				Name:        "inject-alice-google-calendar-token",
				Hosts:       []string{"www.googleapis.com"},
				Paths:       []string{"/calendar/v3/*"},
				Action:      "allow",
				Credentials: []string{"google-calendar"},
			},
		},
	}
	if err := proxyCfg.Validate(); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/calendar/v3/users/me/calendarList", nil)
	if err != nil {
		t.Fatal(err)
	}
	injector := auth.NewInjector(secretStore)
	if err := injector.Apply(ctx, req, proxyCfg, []string{"google-calendar"}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer proxy-access-token" {
		t.Fatalf("unexpected authorization header: %q", got)
	}
}

type staticProvider struct {
	cfg *config.Config
}

func (p staticProvider) Load(context.Context) (*config.Config, error) {
	return p.cfg, nil
}

func (p staticProvider) Watch(ctx context.Context, out chan<- *config.Config) error {
	<-ctx.Done()
	return ctx.Err()
}
