package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type ExternalStore struct {
	webhookURL string
	aead       cipher.AEAD
	client     *http.Client
}

type externalWebhookPayload struct {
	Event        string                  `json:"event"`
	CredentialID string                  `json:"credential_id"`
	Key          string                  `json:"key"`
	Value        *externalEncryptedValue `json:"value,omitempty"`
	SentAt       string                  `json:"sent_at"`
}

type externalEncryptedValue struct {
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func NewExternalStore(webhookURL, secretKey string, client *http.Client) (*ExternalStore, error) {
	if webhookURL == "" {
		return nil, fmt.Errorf("external webhook url is required")
	}
	parsed, err := url.Parse(webhookURL)
	if err != nil {
		return nil, fmt.Errorf("external webhook url is invalid: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("external webhook url must use http or https scheme")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("external webhook url must include a host")
	}
	if secretKey == "" {
		return nil, fmt.Errorf("external webhook secret key is required")
	}
	key := sha256.Sum256([]byte(secretKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &ExternalStore{webhookURL: webhookURL, aead: aead, client: client}, nil
}

func (s *ExternalStore) Get(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (s *ExternalStore) Put(ctx context.Context, credentialID, key, value string) error {
	encrypted, err := s.encrypt([]byte(value), externalAAD(credentialID, key))
	if err != nil {
		return err
	}
	return s.post(ctx, externalWebhookPayload{
		Event:        "secret.put",
		CredentialID: credentialID,
		Key:          key,
		Value:        &encrypted,
		SentAt:       time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *ExternalStore) Delete(ctx context.Context, credentialID, key string) error {
	return s.post(ctx, externalWebhookPayload{
		Event:        "secret.delete",
		CredentialID: credentialID,
		Key:          key,
		SentAt:       time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *ExternalStore) Close() error {
	return nil
}

func (s *ExternalStore) encrypt(plaintext, aad []byte) (externalEncryptedValue, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return externalEncryptedValue{}, err
	}
	ciphertext := s.aead.Seal(nil, nonce, plaintext, aad)
	return externalEncryptedValue{
		Algorithm:  "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func (s *ExternalStore) post(ctx context.Context, payload externalWebhookPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("external webhook returned %s", resp.Status)
	}
	return nil
}

func externalAAD(credentialID, key string) []byte {
	return []byte(credentialID + "\x00" + key)
}
