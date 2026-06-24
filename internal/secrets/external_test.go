package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExternalStorePutPostsEncryptedSecret(t *testing.T) {
	const secretKey = "shared-webhook-key"
	payloads := make(chan externalWebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type: %q", got)
		}
		var payload externalWebhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		payloads <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	store, err := NewExternalStore(server.URL, secretKey, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Put(context.Background(), "google-calendar", "refresh_token", "refresh-token"); err != nil {
		t.Fatal(err)
	}

	payload := <-payloads
	if payload.Event != "secret.put" || payload.CredentialID != "google-calendar" || payload.Key != "refresh_token" {
		t.Fatalf("unexpected payload metadata: %#v", payload)
	}
	if payload.Value == nil {
		t.Fatal("missing encrypted value")
	}
	if payload.Value.Algorithm != "AES-256-GCM" {
		t.Fatalf("unexpected algorithm: %q", payload.Value.Algorithm)
	}
	plaintext := decryptExternalTestValue(t, secretKey, payload.Value, externalAAD("google-calendar", "refresh_token"))
	if plaintext != "refresh-token" {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
}

func TestExternalStoreDeletePostsDeleteEvent(t *testing.T) {
	payloads := make(chan externalWebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload externalWebhookPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		payloads <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	store, err := NewExternalStore(server.URL, "shared-webhook-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Delete(context.Background(), "google-calendar", "refresh_token"); err != nil {
		t.Fatal(err)
	}

	payload := <-payloads
	if payload.Event != "secret.delete" || payload.CredentialID != "google-calendar" || payload.Key != "refresh_token" {
		t.Fatalf("unexpected payload metadata: %#v", payload)
	}
	if payload.Value != nil {
		t.Fatalf("delete payload should not include a value: %#v", payload.Value)
	}
}

func decryptExternalTestValue(t *testing.T, secretKey string, encrypted *externalEncryptedValue, aad []byte) string {
	t.Helper()
	key := sha256.Sum256([]byte(secretKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	return string(plaintext)
}
