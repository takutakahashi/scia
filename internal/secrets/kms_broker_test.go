package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestKMSBrokerClientGenerateAndDecrypt(t *testing.T) {
	requests := make(chan KMSBrokerRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer broker-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request KMSBrokerRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requests <- request
		response := KMSBrokerResponse{PlaintextDEK: base64.RawStdEncoding.EncodeToString(make([]byte, 32))}
		if r.URL.Path == "/api/kms/data-key/generate" {
			response.EncryptedDEK = base64.RawStdEncoding.EncodeToString([]byte("wrapped-dek"))
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewKMSBrokerClient(server.URL, "broker-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	encryptionContext := map[string]string{"scia_credential_id": "alice", "scia_secret_key": "token"}
	generated, err := client.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(generated.CiphertextBlob) != "wrapped-dek" || len(generated.Plaintext) != 32 {
		t.Fatalf("unexpected generate response: %#v", generated)
	}
	decrypted, err := client.Decrypt(context.Background(), &kms.DecryptInput{
		CiphertextBlob:    generated.CiphertextBlob,
		EncryptionContext: encryptionContext,
	})
	if err != nil || len(decrypted.Plaintext) != 32 {
		t.Fatalf("unexpected decrypt response: output=%#v err=%v", decrypted, err)
	}
	generateRequest := <-requests
	decryptRequest := <-requests
	if generateRequest.CredentialID != "alice" || generateRequest.Key != "token" || generateRequest.EncryptedDEK != "" {
		t.Fatalf("unexpected generate request: %#v", generateRequest)
	}
	if decryptRequest.EncryptedDEK != base64.RawStdEncoding.EncodeToString([]byte("wrapped-dek")) {
		t.Fatalf("unexpected decrypt request: %#v", decryptRequest)
	}
}

func TestKMSBrokerClientRequiresRecordContext(t *testing.T) {
	client, err := NewKMSBrokerClient("https://integ.example.com", "token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{}); err == nil {
		t.Fatal("expected missing record context to fail")
	}
}
