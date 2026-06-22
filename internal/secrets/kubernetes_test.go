package secrets

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestKubernetesStorePutGet(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	store, err := NewKubernetesStore(client, "scia", map[string]string{"alice": "scia-oauth-alice"})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Put(ctx, "alice", "refresh_token", "refresh-token"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "alice", "refresh_token")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected stored secret")
	}
	if got != "refresh-token" {
		t.Fatalf("unexpected secret: %q", got)
	}

	secret, err := client.CoreV1().Secrets("scia").Get(ctx, "scia-oauth-alice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["refresh_token"]) != "refresh-token" {
		t.Fatalf("unexpected secret data: %q", secret.Data["refresh_token"])
	}
}

func TestKubernetesStoreUpdatesExistingSecret(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "scia-oauth-alice", Namespace: "scia"},
		Data:       map[string][]byte{"refresh_token": []byte("old-token")},
	})
	store, err := NewKubernetesStore(client, "scia", map[string]string{"alice": "scia-oauth-alice"})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Put(ctx, "alice", "refresh_token", "new-token"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "alice", "refresh_token")
	if err != nil || !ok || got != "new-token" {
		t.Fatalf("unexpected get result: got=%q ok=%v err=%v", got, ok, err)
	}
}

func TestKubernetesStoreRejectsUnknownUser(t *testing.T) {
	store, err := NewKubernetesStore(fake.NewSimpleClientset(), "scia", map[string]string{"alice": "scia-oauth-alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), "bob", "refresh_token", "token"); err == nil {
		t.Fatal("expected unknown user error")
	}
}

func TestKubernetesStoreDynamicUserCreatesSecret(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	store, err := NewKubernetesStore(client, "scia", nil, KubernetesStoreOptions{
		DynamicUsers:                true,
		DynamicUserSecretNamePrefix: "scia-oauth-",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Put(ctx, "bob", "refresh_token", "token"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "bob", "refresh_token")
	if err != nil || !ok || got != "token" {
		t.Fatalf("unexpected get result: got=%q ok=%v err=%v", got, ok, err)
	}
	secret, err := client.CoreV1().Secrets("scia").Get(ctx, "scia-oauth-bob", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["refresh_token"]) != "token" {
		t.Fatalf("unexpected secret data: %q", secret.Data["refresh_token"])
	}
}

func TestKubernetesStoreRejectsInvalidDynamicUser(t *testing.T) {
	store, err := NewKubernetesStore(fake.NewSimpleClientset(), "scia", nil, KubernetesStoreOptions{
		DynamicUsers: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), "Bob", "refresh_token", "token"); err == nil {
		t.Fatal("expected invalid dynamic user error")
	}
}
