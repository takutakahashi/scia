package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const kmsBrokerKeyID = "scia-kms-broker"

type KMSBrokerClient struct {
	baseURL string
	token   string
	client  *http.Client
}

type KMSBrokerRequest struct {
	CredentialID string `json:"credentialId"`
	Key          string `json:"key"`
	EncryptedDEK string `json:"encryptedDek,omitempty"`
}

type KMSBrokerResponse struct {
	PlaintextDEK string `json:"plaintextDek"`
	EncryptedDEK string `json:"encryptedDek,omitempty"`
}

func NewKMSBrokerClient(baseURL, token string, client *http.Client) (*KMSBrokerClient, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("KMS broker URL must be a valid http or https URL")
	}
	if token == "" {
		return nil, fmt.Errorf("KMS broker token is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &KMSBrokerClient{baseURL: parsed.String(), token: token, client: client}, nil
}

func (c *KMSBrokerClient) GenerateDataKey(ctx context.Context, input *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	credentialID, key, err := brokerRecord(input.EncryptionContext)
	if err != nil {
		return nil, err
	}
	response, err := c.call(ctx, "/api/kms/data-key/generate", KMSBrokerRequest{CredentialID: credentialID, Key: key})
	if err != nil {
		return nil, err
	}
	plaintext, encrypted, err := decodeBrokerResponse(response, true)
	if err != nil {
		return nil, err
	}
	return &kms.GenerateDataKeyOutput{Plaintext: plaintext, CiphertextBlob: encrypted, KeyId: aws.String(kmsBrokerKeyID)}, nil
}

func (c *KMSBrokerClient) Decrypt(ctx context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	credentialID, key, err := brokerRecord(input.EncryptionContext)
	if err != nil {
		return nil, err
	}
	response, err := c.call(ctx, "/api/kms/data-key/decrypt", KMSBrokerRequest{
		CredentialID: credentialID,
		Key:          key,
		EncryptedDEK: base64.RawStdEncoding.EncodeToString(input.CiphertextBlob),
	})
	if err != nil {
		return nil, err
	}
	plaintext, _, err := decodeBrokerResponse(response, false)
	if err != nil {
		return nil, err
	}
	return &kms.DecryptOutput{Plaintext: plaintext, KeyId: aws.String(kmsBrokerKeyID)}, nil
}

func (c *KMSBrokerClient) call(ctx context.Context, path string, payload KMSBrokerRequest) (KMSBrokerResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return KMSBrokerResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return KMSBrokerResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return KMSBrokerResponse{}, fmt.Errorf("KMS broker request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return KMSBrokerResponse{}, fmt.Errorf("KMS broker returned %s", resp.Status)
	}
	var result KMSBrokerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return KMSBrokerResponse{}, fmt.Errorf("decode KMS broker response: %w", err)
	}
	return result, nil
}

func brokerRecord(encryptionContext map[string]string) (string, string, error) {
	credentialID := encryptionContext["scia_credential_id"]
	key := encryptionContext["scia_secret_key"]
	if credentialID == "" || key == "" {
		return "", "", fmt.Errorf("KMS broker requires scia record encryption context")
	}
	return credentialID, key, nil
}

func decodeBrokerResponse(response KMSBrokerResponse, requireEncrypted bool) ([]byte, []byte, error) {
	plaintext, err := base64.RawStdEncoding.DecodeString(response.PlaintextDEK)
	if err != nil || len(plaintext) != 32 {
		return nil, nil, fmt.Errorf("KMS broker returned an invalid plaintext data key")
	}
	if !requireEncrypted {
		return plaintext, nil, nil
	}
	encrypted, err := base64.RawStdEncoding.DecodeString(response.EncryptedDEK)
	if err != nil || len(encrypted) == 0 {
		zeroBytes(plaintext)
		return nil, nil, fmt.Errorf("KMS broker returned an invalid encrypted data key")
	}
	return plaintext, encrypted, nil
}
