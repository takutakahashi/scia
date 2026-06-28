package serviceinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

const SecretKey = "_scia_service_config_v1"

type storedService struct {
	ID      string               `json:"id"`
	Service config.ServiceConfig `json:"service"`
}

type Response struct {
	ID      string               `json:"id"`
	Service config.ServiceConfig `json:"service"`
}

func Put(ctx context.Context, store secrets.Store, serviceID string, service config.ServiceConfig) error {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		return fmt.Errorf("service id is required")
	}
	normalized, err := Normalize(serviceID, service)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(storedService{ID: serviceID, Service: normalized})
	if err != nil {
		return err
	}
	return store.Put(ctx, serviceID, SecretKey, string(payload))
}

func Get(ctx context.Context, store secrets.Store, serviceID string) (config.ServiceConfig, bool, error) {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		return config.ServiceConfig{}, false, nil
	}
	raw, ok, err := store.Get(ctx, serviceID, SecretKey)
	if err != nil || !ok {
		return config.ServiceConfig{}, ok, err
	}
	var stored storedService
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return config.ServiceConfig{}, true, err
	}
	if stored.ID != "" && stored.ID != serviceID {
		return config.ServiceConfig{}, true, fmt.Errorf("stored service id %q does not match %q", stored.ID, serviceID)
	}
	normalized, err := Normalize(serviceID, stored.Service)
	if err != nil {
		return config.ServiceConfig{}, true, err
	}
	return normalized, true, nil
}

func Fetch(ctx context.Context, client *http.Client, metadataURL, token, serviceID string) (config.ServiceConfig, error) {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		return config.ServiceConfig{}, fmt.Errorf("service id is required")
	}
	endpoint, err := serviceMetadataURL(metadataURL, serviceID)
	if err != nil {
		return config.ServiceConfig{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return config.ServiceConfig{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return config.ServiceConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return config.ServiceConfig{}, fmt.Errorf("metadata service %q not found", serviceID)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return config.ServiceConfig{}, fmt.Errorf("metadata endpoint returned %s", resp.Status)
	}
	var payload Response
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return config.ServiceConfig{}, err
	}
	if payload.ID != "" && payload.ID != serviceID {
		return config.ServiceConfig{}, fmt.Errorf("metadata service id %q does not match %q", payload.ID, serviceID)
	}
	return Normalize(serviceID, payload.Service)
}

func Normalize(serviceID string, service config.ServiceConfig) (config.ServiceConfig, error) {
	if serviceID == "" {
		return config.ServiceConfig{}, fmt.Errorf("service id is required")
	}
	if len(service.Hosts) == 0 {
		return config.ServiceConfig{}, fmt.Errorf("service %q hosts are required", serviceID)
	}
	for i := range service.Hosts {
		host := &service.Hosts[i]
		if (host.Host == "") == (host.HostSuffix == "") {
			return config.ServiceConfig{}, fmt.Errorf("service %q hosts[%d] must set exactly one of host or hostSuffix", serviceID, i)
		}
		if host.AuthMethod == "" {
			if service.OAuth != nil {
				host.AuthMethod = "bearer"
			} else {
				host.AuthMethod = "none"
			}
		}
		switch host.AuthMethod {
		case "bearer", "basic-x-access-token", "basic", "none":
		default:
			return config.ServiceConfig{}, fmt.Errorf("service %q hosts[%d] has unsupported authMethod %q", serviceID, i, host.AuthMethod)
		}
	}
	if service.OAuth != nil {
		if service.OAuth.CredentialID == "" {
			service.OAuth.CredentialID = serviceID
		}
		if service.OAuth.AuthURL != "" {
			if err := validateURL("authUrl", service.OAuth.AuthURL); err != nil {
				return config.ServiceConfig{}, err
			}
		}
		if service.OAuth.TokenURL != "" {
			if err := validateURL("tokenUrl", service.OAuth.TokenURL); err != nil {
				return config.ServiceConfig{}, err
			}
		}
		if service.OAuth.RevokeURL != "" {
			if err := validateURL("revokeUrl", service.OAuth.RevokeURL); err != nil {
				return config.ServiceConfig{}, err
			}
		}
		if service.OAuth.ScopeParam.Separator == "" {
			service.OAuth.ScopeParam.Separator = " "
		}
		if service.OAuth.TokenRequest.BodyFormat == "" {
			service.OAuth.TokenRequest.BodyFormat = "form"
		}
		switch service.OAuth.TokenRequest.BodyFormat {
		case "form", "json":
		default:
			return config.ServiceConfig{}, fmt.Errorf("service %q oauth.tokenRequest.bodyFormat must be form or json", serviceID)
		}
		if service.OAuth.TokenRequest.ClientAuth == "" {
			service.OAuth.TokenRequest.ClientAuth = "body"
		}
		switch service.OAuth.TokenRequest.ClientAuth {
		case "body", "basic":
		default:
			return config.ServiceConfig{}, fmt.Errorf("service %q oauth.tokenRequest.clientAuth must be body or basic", serviceID)
		}
	}
	for i, h := range service.Injection.Headers {
		if h.Name == "" || h.Value == "" {
			return config.ServiceConfig{}, fmt.Errorf("service %q injection.headers[%d] requires name and value", serviceID, i)
		}
	}
	for i, q := range service.Injection.Query {
		if q.Name == "" || q.Value == "" {
			return config.ServiceConfig{}, fmt.Errorf("service %q injection.query[%d] requires name and value", serviceID, i)
		}
	}
	return service, nil
}

func serviceMetadataURL(metadataURL, serviceID string) (string, error) {
	metadataURL = strings.TrimSpace(metadataURL)
	if metadataURL == "" {
		return "", fmt.Errorf("metadataUrl is required")
	}
	escaped := url.PathEscape(serviceID)
	if strings.Contains(metadataURL, "{service}") {
		return strings.ReplaceAll(metadataURL, "{service}", escaped), nil
	}
	parsed, err := url.Parse(metadataURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("metadataUrl must use http or https scheme")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("metadataUrl must include a host")
	}
	parsed.Path = path.Join(parsed.Path, escaped)
	return parsed.String(), nil
}

func validateURL(field, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", field, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must use http or https scheme", field)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", field)
	}
	return nil
}
