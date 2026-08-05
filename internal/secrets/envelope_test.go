package secrets

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestAWSKMSEnvelopeStoreRoundTripAndCiphertextAtRest(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	fake := newFakeKMS()
	store := newTestEnvelopeStore(t, inner, fake, time.Minute, 10)

	if err := store.Put(ctx, "alice", "access_token", "secret-token"); err != nil {
		t.Fatal(err)
	}
	stored := inner.values["alice\x00access_token"]
	if !strings.HasPrefix(stored, envelopePrefix) {
		t.Fatalf("value was not stored as an AWS KMS envelope: %q", stored)
	}
	if strings.Contains(stored, "secret-token") {
		t.Fatal("stored envelope contains plaintext")
	}

	// A fresh store simulates a restart and verifies that KMS can unwrap the
	// persisted DEK with the reconstructed encryption context.
	reader := newTestEnvelopeStore(t, inner, fake, time.Minute, 10)
	got, ok, err := reader.Get(ctx, "alice", "access_token")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != "secret-token" {
		t.Fatalf("unexpected result: got=%q ok=%v", got, ok)
	}
	if fake.generateCalls != 1 || fake.decryptCalls != 1 {
		t.Fatalf("unexpected KMS calls: generate=%d decrypt=%d", fake.generateCalls, fake.decryptCalls)
	}
	wantContext := map[string]string{
		"environment":        "test",
		"scia_credential_id": "alice",
		"scia_secret_key":    "access_token",
	}
	if !maps.Equal(fake.lastGenerateContext, wantContext) || !maps.Equal(fake.lastDecryptContext, wantContext) {
		t.Fatalf("unexpected encryption context: generate=%v decrypt=%v", fake.lastGenerateContext, fake.lastDecryptContext)
	}
}

func TestAWSKMSEnvelopeStoreUsesUniqueKMSDataKeys(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	store := newTestEnvelopeStore(t, inner, newFakeKMS(), time.Minute, 10)

	if err := store.Put(ctx, "alice", "token", "same-value"); err != nil {
		t.Fatal(err)
	}
	first := inner.values["alice\x00token"]
	if err := store.Put(ctx, "alice", "token", "same-value"); err != nil {
		t.Fatal(err)
	}
	if second := inner.values["alice\x00token"]; first == second {
		t.Fatal("two writes produced the same envelope")
	}
}

func TestAWSKMSEnvelopeStoreCachesUnwrappedDataKey(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	fake := newFakeKMS()
	store := newTestEnvelopeStore(t, inner, fake, time.Minute, 10)
	if err := store.Put(ctx, "alice", "token", "secret"); err != nil {
		t.Fatal(err)
	}
	reader := newTestEnvelopeStore(t, inner, fake, time.Minute, 10)
	for range 2 {
		if _, _, err := reader.Get(ctx, "alice", "token"); err != nil {
			t.Fatal(err)
		}
	}
	if fake.decryptCalls != 1 {
		t.Fatalf("expected one KMS decrypt call, got %d", fake.decryptCalls)
	}
}

func TestAWSKMSEnvelopeStoreDisablesCacheWithZeroTTL(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	fake := newFakeKMS()
	store := newTestEnvelopeStore(t, inner, fake, 0, 10)
	if err := store.Put(ctx, "alice", "token", "secret"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := store.Get(ctx, "alice", "token"); err != nil {
			t.Fatal(err)
		}
	}
	if fake.decryptCalls != 2 {
		t.Fatalf("expected two KMS decrypt calls, got %d", fake.decryptCalls)
	}
}

func TestAWSKMSEnvelopeStoreRejectsPlaintextAndMovedCiphertext(t *testing.T) {
	ctx := context.Background()
	inner := &memoryEnvelopeStore{values: map[string]string{"alice\x00legacy": "legacy-value"}}
	store := newTestEnvelopeStore(t, inner, newFakeKMS(), time.Minute, 10)
	if _, _, err := store.Get(ctx, "alice", "legacy"); err == nil {
		t.Fatal("expected plaintext value to fail")
	}
	if err := store.Put(ctx, "alice", "token", "secret"); err != nil {
		t.Fatal(err)
	}
	inner.values["bob\x00token"] = inner.values["alice\x00token"]
	if _, _, err := store.Get(ctx, "bob", "token"); err == nil {
		t.Fatal("expected ciphertext moved to another user to fail")
	}
}

func TestNewAWSKMSEnvelopeStoreValidatesOptions(t *testing.T) {
	inner := &memoryEnvelopeStore{values: map[string]string{}}
	fake := newFakeKMS()
	if _, err := NewAWSKMSEnvelopeStore(inner, fake, AWSKMSEnvelopeOptions{}); err == nil {
		t.Fatal("expected missing key ID to fail")
	}
	if _, err := NewAWSKMSEnvelopeStore(inner, fake, AWSKMSEnvelopeOptions{
		KeyID:             "key-id",
		EncryptionContext: map[string]string{"scia_credential_id": "override"},
	}); err == nil {
		t.Fatal("expected reserved encryption context to fail")
	}
}

func newTestEnvelopeStore(t *testing.T, inner Store, fake *fakeKMS, ttl time.Duration, maxEntries int) *EnvelopeStore {
	t.Helper()
	store, err := NewAWSKMSEnvelopeStore(inner, fake, AWSKMSEnvelopeOptions{
		KeyID:             "test-key",
		EncryptionContext: map[string]string{"environment": "test"},
		CacheTTL:          ttl,
		CacheMaxEntries:   maxEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type fakeKMSRecord struct {
	plaintext         []byte
	keyID             string
	encryptionContext map[string]string
}

type fakeKMS struct {
	records             map[string]fakeKMSRecord
	generateCalls       int
	decryptCalls        int
	lastGenerateContext map[string]string
	lastDecryptContext  map[string]string
}

func newFakeKMS() *fakeKMS {
	return &fakeKMS{records: map[string]fakeKMSRecord{}}
}

func (f *fakeKMS) GenerateDataKey(_ context.Context, input *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if input.KeySpec != types.DataKeySpecAes256 {
		return nil, fmt.Errorf("unexpected key spec %q", input.KeySpec)
	}
	f.generateCalls++
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(f.generateCalls + i)
	}
	blob := []byte(fmt.Sprintf("encrypted-dek-%d", f.generateCalls))
	contextCopy := maps.Clone(input.EncryptionContext)
	f.records[string(blob)] = fakeKMSRecord{plaintext: mapsCloneBytes(plaintext), keyID: aws.ToString(input.KeyId), encryptionContext: contextCopy}
	f.lastGenerateContext = contextCopy
	return &kms.GenerateDataKeyOutput{Plaintext: plaintext, CiphertextBlob: blob, KeyId: input.KeyId}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decryptCalls++
	f.lastDecryptContext = maps.Clone(input.EncryptionContext)
	record, ok := f.records[string(input.CiphertextBlob)]
	if !ok || record.keyID != aws.ToString(input.KeyId) || !maps.Equal(record.encryptionContext, input.EncryptionContext) {
		return nil, fmt.Errorf("KMS ciphertext, key, or encryption context mismatch")
	}
	return &kms.DecryptOutput{Plaintext: mapsCloneBytes(record.plaintext), KeyId: input.KeyId}, nil
}

func mapsCloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

type memoryEnvelopeStore struct {
	values map[string]string
}

func (s *memoryEnvelopeStore) Get(_ context.Context, credentialID, key string) (string, bool, error) {
	value, ok := s.values[credentialID+"\x00"+key]
	return value, ok, nil
}

func (s *memoryEnvelopeStore) Put(_ context.Context, credentialID, key, value string) error {
	s.values[credentialID+"\x00"+key] = value
	return nil
}

func (s *memoryEnvelopeStore) Delete(_ context.Context, credentialID, key string) error {
	delete(s.values, credentialID+"\x00"+key)
	return nil
}

func (s *memoryEnvelopeStore) Close() error { return nil }
