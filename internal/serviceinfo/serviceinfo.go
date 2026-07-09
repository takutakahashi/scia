package serviceinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

const SecretKey = "_scia_service_config_v1"
const IndexCredentialID = "scia-service-metadata"
const IndexSecretKey = "service_ids_v1"

type storedService struct {
	ID      string               `json:"id"`
	Service config.ServiceConfig `json:"service"`
}

type Response struct {
	ID      string               `json:"id"`
	Service config.ServiceConfig `json:"service"`
}

type ListResponse struct {
	Services []Response `json:"services"`
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
	payload, err := json.Marshal(storedService{ID: serviceID, Service: SanitizeForClient(normalized)})
	if err != nil {
		return err
	}
	if err := store.Put(ctx, serviceID, SecretKey, string(payload)); err != nil {
		return err
	}
	return AddToIndex(ctx, store, serviceID)
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

func AddToIndex(ctx context.Context, store secrets.Store, serviceID string) error {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		return fmt.Errorf("service id is required")
	}
	ids, err := ListIDs(ctx, store)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id == serviceID {
			return nil
		}
	}
	ids = append(ids, serviceID)
	payload, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return store.Put(ctx, IndexCredentialID, IndexSecretKey, string(payload))
}

func ListIDs(ctx context.Context, store secrets.Store) ([]string, error) {
	raw, ok, err := store.Get(ctx, IndexCredentialID, IndexSecretKey)
	if err != nil || !ok {
		return nil, err
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, err
	}
	out := ids[:0]
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func MatchingStoredIDs(ctx context.Context, store secrets.Store, host, reqPath string) ([]string, error) {
	ids, err := ListIDs(ctx, store)
	if err != nil {
		return nil, err
	}
	matches := make([]string, 0, len(ids))
	for _, id := range ids {
		service, ok, err := Get(ctx, store, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if _, ok := HostRule(service, host, reqPath); ok {
			matches = append(matches, id)
		}
	}
	return matches, nil
}

func HostRule(service config.ServiceConfig, host, reqPath string) (config.ServiceHostRule, bool) {
	hostOnly := strings.ToLower(host)
	if splitHost, _, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = splitHost
	}
	for _, rule := range service.Hosts {
		if rule.Host != "" && strings.ToLower(rule.Host) != hostOnly {
			continue
		}
		if rule.HostSuffix != "" {
			suffix := strings.ToLower(rule.HostSuffix)
			if !strings.HasSuffix(hostOnly, suffix) || len(hostOnly) <= len(suffix) {
				continue
			}
		}
		if rule.PathPrefix != "" && !strings.HasPrefix(reqPath, rule.PathPrefix) {
			continue
		}
		return rule, true
	}
	return config.ServiceHostRule{}, false
}

func HostMatches(service config.ServiceConfig, host string) bool {
	hostOnly := strings.ToLower(host)
	if splitHost, _, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = splitHost
	}
	for _, rule := range service.Hosts {
		if rule.Host != "" && strings.ToLower(rule.Host) == hostOnly {
			return true
		}
		if rule.HostSuffix != "" {
			suffix := strings.ToLower(rule.HostSuffix)
			if strings.HasSuffix(hostOnly, suffix) && len(hostOnly) > len(suffix) {
				return true
			}
		}
	}
	return false
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

func FetchAll(ctx context.Context, client *http.Client, metadataURL, token string) ([]Response, error) {
	endpoint, err := serviceListURL(metadataURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("metadata endpoint returned %s", resp.Status)
	}
	var payload ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	services := make([]Response, 0, len(payload.Services))
	for _, item := range payload.Services {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			return nil, fmt.Errorf("metadata service id is required")
		}
		normalized, err := Normalize(id, item.Service)
		if err != nil {
			return nil, err
		}
		services = append(services, Response{ID: id, Service: normalized})
	}
	return services, nil
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

func SanitizeForClient(service config.ServiceConfig) config.ServiceConfig {
	if service.OAuth != nil {
		oauth := *service.OAuth
		oauth.ClientID = ""
		oauth.ClientSecret = ""
		service.OAuth = &oauth
	}
	return service
}

func serviceListURL(metadataURL string) (string, error) {
	metadataURL = strings.TrimSpace(metadataURL)
	if metadataURL == "" {
		return "", fmt.Errorf("metadataUrl is required")
	}
	if strings.Contains(metadataURL, "{service}") {
		return "", fmt.Errorf("metadataUrl with {service} cannot be used for service list")
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
	return parsed.String(), nil
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
