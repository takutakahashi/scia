package secrets

import (
	"context"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestKubernetesIntegrationPutGet(t *testing.T) {
	if os.Getenv("SCIA_K8S_INTEGRATION") != "1" {
		t.Skip("set SCIA_K8S_INTEGRATION=1 to run kubernetes integration tests")
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{},
		ErrorIfCRDPathMissing: false,
	}
	if assetsDir := os.Getenv("KUBEBUILDER_ASSETS"); assetsDir != "" {
		env.BinaryAssetsDirectory = assetsDir
	}

	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		_ = env.Stop()
	})

	ctx := context.Background()
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "scia-test"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	store, err := NewKubernetesStore(client, namespace, map[string]string{"alice": "scia-oauth-alice"})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Put(ctx, "alice", "refresh_token", "integration-refresh-token"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "alice", "refresh_token")
	if err != nil || !ok || got != "integration-refresh-token" {
		t.Fatalf("unexpected get result: got=%q ok=%v err=%v", got, ok, err)
	}

	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, "scia-oauth-alice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["refresh_token"]) != "integration-refresh-token" {
		t.Fatalf("unexpected secret data: %q", secret.Data["refresh_token"])
	}
}

func TestKubernetesIntegrationFromRESTConfig(t *testing.T) {
	if os.Getenv("SCIA_K8S_INTEGRATION") != "1" {
		t.Skip("set SCIA_K8S_INTEGRATION=1 to run kubernetes integration tests")
	}

	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		_ = env.Stop()
	})

	ctx := context.Background()
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "default"
	store, err := NewKubernetesStoreFromRESTConfig(cfg, namespace, map[string]string{"alice": "scia-oauth-alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "alice", "refresh_token", "from-rest-config"); err != nil {
		t.Fatal(err)
	}
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, "scia-oauth-alice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["refresh_token"]) != "from-rest-config" {
		t.Fatalf("unexpected secret data: %q", secret.Data["refresh_token"])
	}
}
