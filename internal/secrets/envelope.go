package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const envelopePrefix = "scia:envelope:v1:"

type envelopePayload struct {
	WrappedDEK string `json:"wrappedDek"`
	DEKNonce   string `json:"dekNonce"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
}

// EnvelopeStore encrypts each value with a random data encryption key (DEK),
// then encrypts that DEK with the configured key encryption key (KEK).
type EnvelopeStore struct {
	store Store
	kek   cipher.AEAD
}

func NewEnvelopeStore(store Store, encodedKey string) (*EnvelopeStore, error) {
	key, err := decodeEnvelopeKey(encodedKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	kek, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EnvelopeStore{store: store, kek: kek}, nil
}

func decodeEnvelopeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("key must be base64-encoded: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must decode to exactly 32 bytes, got %d", len(key))
	}
	return key, nil
}

func (s *EnvelopeStore) Get(ctx context.Context, credentialID, key string) (string, bool, error) {
	stored, ok, err := s.store.Get(ctx, credentialID, key)
	if err != nil || !ok {
		return stored, ok, err
	}
	if !strings.HasPrefix(stored, envelopePrefix) {
		return "", false, fmt.Errorf("decrypt secret %q/%q: value is not an encrypted envelope", credentialID, key)
	}
	value, err := s.decrypt(credentialID, key, strings.TrimPrefix(stored, envelopePrefix))
	if err != nil {
		return "", false, fmt.Errorf("decrypt secret %q/%q: %w", credentialID, key, err)
	}
	return value, true, nil
}

func (s *EnvelopeStore) Put(ctx context.Context, credentialID, key, value string) error {
	stored, err := s.encrypt(credentialID, key, value)
	if err != nil {
		return fmt.Errorf("encrypt secret %q/%q: %w", credentialID, key, err)
	}
	return s.store.Put(ctx, credentialID, key, stored)
}

func (s *EnvelopeStore) Delete(ctx context.Context, credentialID, key string) error {
	return s.store.Delete(ctx, credentialID, key)
}

func (s *EnvelopeStore) Close() error {
	return s.store.Close()
}

func (s *EnvelopeStore) encrypt(credentialID, key, value string) (string, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", err
	}
	dataAEAD, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	aad := envelopeAAD(credentialID, key)
	dekNonce := make([]byte, s.kek.NonceSize())
	nonce := make([]byte, dataAEAD.NonceSize())
	if _, err := rand.Read(dekNonce); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := envelopePayload{
		WrappedDEK: base64.RawStdEncoding.EncodeToString(s.kek.Seal(nil, dekNonce, dek, append([]byte("dek\x00"), aad...))),
		DEKNonce:   base64.RawStdEncoding.EncodeToString(dekNonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(dataAEAD.Seal(nil, nonce, []byte(value), append([]byte("value\x00"), aad...))),
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return envelopePrefix + base64.RawStdEncoding.EncodeToString(raw), nil
}

func (s *EnvelopeStore) decrypt(credentialID, key, encoded string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode envelope: %w", err)
	}
	var payload envelopePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("decode envelope: %w", err)
	}
	wrappedDEK, err := base64.RawStdEncoding.DecodeString(payload.WrappedDEK)
	if err != nil {
		return "", fmt.Errorf("decode wrapped DEK: %w", err)
	}
	dekNonce, err := base64.RawStdEncoding.DecodeString(payload.DEKNonce)
	if err != nil {
		return "", fmt.Errorf("decode DEK nonce: %w", err)
	}
	aad := envelopeAAD(credentialID, key)
	dek, err := s.kek.Open(nil, dekNonce, wrappedDEK, append([]byte("dek\x00"), aad...))
	if err != nil {
		return "", fmt.Errorf("unwrap DEK: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", err
	}
	dataAEAD, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	plaintext, err := dataAEAD.Open(nil, nonce, ciphertext, append([]byte("value\x00"), aad...))
	if err != nil {
		return "", fmt.Errorf("decrypt value: %w", err)
	}
	return string(plaintext), nil
}

func envelopeAAD(credentialID, key string) []byte {
	return []byte(credentialID + "\x00" + key)
}
