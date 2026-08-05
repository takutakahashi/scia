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
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const envelopePrefix = "scia:envelope:aws-kms:v1:"

type envelopePayload struct {
	EncryptedDEK string `json:"encryptedDek"`
	Ciphertext   string `json:"ciphertext"`
	Nonce        string `json:"nonce"`
}

type awsKMSClient interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type AWSKMSEnvelopeOptions struct {
	KeyID             string
	EncryptionContext map[string]string
	CacheTTL          time.Duration
	CacheMaxEntries   int
}

// EnvelopeStore encrypts every value with a unique KMS-generated data key.
// Only the KMS-encrypted data key and AES-256-GCM ciphertext are persisted.
type EnvelopeStore struct {
	store             Store
	kms               awsKMSClient
	keyID             string
	encryptionContext map[string]string
	cache             *dekCache
}

func NewAWSKMSEnvelopeStore(store Store, client awsKMSClient, options AWSKMSEnvelopeOptions) (*EnvelopeStore, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if client == nil {
		return nil, fmt.Errorf("AWS KMS client is required")
	}
	if options.KeyID == "" {
		return nil, fmt.Errorf("AWS KMS key ID is required")
	}
	contextCopy := make(map[string]string, len(options.EncryptionContext))
	for key, value := range options.EncryptionContext {
		if key == "scia_credential_id" || key == "scia_secret_key" {
			return nil, fmt.Errorf("encryption context key %q is reserved", key)
		}
		contextCopy[key] = value
	}
	return &EnvelopeStore{
		store:             store,
		kms:               client,
		keyID:             options.KeyID,
		encryptionContext: contextCopy,
		cache:             newDEKCache(options.CacheTTL, options.CacheMaxEntries),
	}, nil
}

func (s *EnvelopeStore) Get(ctx context.Context, credentialID, key string) (string, bool, error) {
	stored, ok, err := s.store.Get(ctx, credentialID, key)
	if err != nil || !ok {
		return stored, ok, err
	}
	if !strings.HasPrefix(stored, envelopePrefix) {
		return "", false, fmt.Errorf("decrypt secret %q/%q: value is not an AWS KMS envelope", credentialID, key)
	}
	value, err := s.decrypt(ctx, credentialID, key, strings.TrimPrefix(stored, envelopePrefix))
	if err != nil {
		return "", false, fmt.Errorf("decrypt secret %q/%q: %w", credentialID, key, err)
	}
	return value, true, nil
}

func (s *EnvelopeStore) Put(ctx context.Context, credentialID, key, value string) error {
	stored, err := s.encrypt(ctx, credentialID, key, value)
	if err != nil {
		return fmt.Errorf("encrypt secret %q/%q: %w", credentialID, key, err)
	}
	return s.store.Put(ctx, credentialID, key, stored)
}

func (s *EnvelopeStore) Delete(ctx context.Context, credentialID, key string) error {
	return s.store.Delete(ctx, credentialID, key)
}

func (s *EnvelopeStore) Close() error {
	s.cache.clear()
	return s.store.Close()
}

func (s *EnvelopeStore) encrypt(ctx context.Context, credentialID, key, value string) (string, error) {
	kmsContext := s.kmsEncryptionContext(credentialID, key)
	generated, err := s.kms.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:             aws.String(s.keyID),
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: kmsContext,
	})
	if err != nil {
		return "", fmt.Errorf("generate data key: %w", err)
	}
	if len(generated.Plaintext) != 32 || len(generated.CiphertextBlob) == 0 {
		zeroBytes(generated.Plaintext)
		return "", fmt.Errorf("AWS KMS returned an invalid data key")
	}
	defer zeroBytes(generated.Plaintext)

	dataAEAD, err := dataAEAD(generated.Plaintext)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, dataAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := envelopePayload{
		EncryptedDEK: base64.RawStdEncoding.EncodeToString(generated.CiphertextBlob),
		Ciphertext:   base64.RawStdEncoding.EncodeToString(dataAEAD.Seal(nil, nonce, []byte(value), envelopeAAD(credentialID, key))),
		Nonce:        base64.RawStdEncoding.EncodeToString(nonce),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	s.cache.put(payload.EncryptedDEK, generated.Plaintext)
	return envelopePrefix + base64.RawStdEncoding.EncodeToString(raw), nil
}

func (s *EnvelopeStore) decrypt(ctx context.Context, credentialID, key, encoded string) (string, error) {
	payload, encryptedDEK, err := decodeEnvelope(encoded)
	if err != nil {
		return "", err
	}
	dek, ok := s.cache.get(payload.EncryptedDEK)
	if !ok {
		decrypted, err := s.kms.Decrypt(ctx, &kms.DecryptInput{
			CiphertextBlob:    encryptedDEK,
			EncryptionContext: s.kmsEncryptionContext(credentialID, key),
			KeyId:             aws.String(s.keyID),
		})
		if err != nil {
			return "", fmt.Errorf("unwrap data key: %w", err)
		}
		if len(decrypted.Plaintext) != 32 {
			zeroBytes(decrypted.Plaintext)
			return "", fmt.Errorf("AWS KMS returned an invalid data key")
		}
		dek = decrypted.Plaintext
		s.cache.put(payload.EncryptedDEK, dek)
	}
	defer zeroBytes(dek)

	dataAEAD, err := dataAEAD(dek)
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
	plaintext, err := dataAEAD.Open(nil, nonce, ciphertext, envelopeAAD(credentialID, key))
	if err != nil {
		return "", fmt.Errorf("decrypt value: %w", err)
	}
	return string(plaintext), nil
}

func decodeEnvelope(encoded string) (envelopePayload, []byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return envelopePayload{}, nil, fmt.Errorf("decode envelope: %w", err)
	}
	var payload envelopePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return envelopePayload{}, nil, fmt.Errorf("decode envelope: %w", err)
	}
	encryptedDEK, err := base64.RawStdEncoding.DecodeString(payload.EncryptedDEK)
	if err != nil || len(encryptedDEK) == 0 {
		return envelopePayload{}, nil, fmt.Errorf("decode encrypted data key: invalid value")
	}
	return payload, encryptedDEK, nil
}

func dataAEAD(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *EnvelopeStore) kmsEncryptionContext(credentialID, key string) map[string]string {
	result := make(map[string]string, len(s.encryptionContext)+2)
	for contextKey, value := range s.encryptionContext {
		result[contextKey] = value
	}
	result["scia_credential_id"] = credentialID
	result["scia_secret_key"] = key
	return result
}

func envelopeAAD(credentialID, key string) []byte {
	return []byte(credentialID + "\x00" + key)
}

type dekCacheEntry struct {
	dek       []byte
	expiresAt time.Time
	createdAt time.Time
}

type dekCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]dekCacheEntry
}

func newDEKCache(ttl time.Duration, maxEntries int) *dekCache {
	return &dekCache{ttl: ttl, maxEntries: maxEntries, entries: map[string]dekCacheEntry{}}
}

func (c *dekCache) get(key string) ([]byte, bool) {
	if c.ttl <= 0 || c.maxEntries <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !time.Now().Before(entry.expiresAt) {
		zeroBytes(entry.dek)
		delete(c.entries, key)
		return nil, false
	}
	return append([]byte(nil), entry.dek...), true
}

func (c *dekCache) put(key string, dek []byte) {
	if c.ttl <= 0 || c.maxEntries <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for cacheKey, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			zeroBytes(entry.dek)
			delete(c.entries, cacheKey)
		}
	}
	for len(c.entries) >= c.maxEntries {
		var oldestKey string
		var oldest time.Time
		for cacheKey, entry := range c.entries {
			if oldestKey == "" || entry.createdAt.Before(oldest) {
				oldestKey, oldest = cacheKey, entry.createdAt
			}
		}
		entry := c.entries[oldestKey]
		zeroBytes(entry.dek)
		delete(c.entries, oldestKey)
	}
	c.entries[key] = dekCacheEntry{
		dek:       append([]byte(nil), dek...),
		expiresAt: now.Add(c.ttl),
		createdAt: now,
	}
}

func (c *dekCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		zeroBytes(entry.dek)
		delete(c.entries, key)
	}
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
