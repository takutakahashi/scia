package authsync

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/secrets"
)

type Client struct {
	store   *config.Store
	secrets secrets.Store
	client  *http.Client
	logger  *slog.Logger
}

func NewClient(store *config.Store, secretStore secrets.Store, logger *slog.Logger) *Client {
	return &Client{
		store:   store,
		secrets: secretStore,
		client:  &http.Client{Timeout: 0},
		logger:  logger,
	}
}

func (c *Client) Run(ctx context.Context) {
	for {
		if err := c.connect(ctx); err != nil && ctx.Err() == nil {
			c.logger.Warn("auth sync connection stopped", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	cfg := c.store.Get().Server.AuthSync
	syncURL := config.HeaderValueFromEnv(cfg.URL)
	if syncURL == "" {
		return fmt.Errorf("server.authSync.url is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, syncURL, nil)
	if err != nil {
		return err
	}
	if token := config.HeaderValueFromEnv(cfg.Token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cfg.ProxyID != "" {
		req.Header.Set("X-Scia-Proxy-ID", cfg.ProxyID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("auth sync server returned %s", resp.Status)
	}
	c.logger.Info("auth sync connected", "url", syncURL)
	return c.readEvents(ctx, resp)
}

func (c *Client) readEvents(ctx context.Context, resp *http.Response) error {
	scanner := bufio.NewScanner(resp.Body)
	var data strings.Builder
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Text()
		if line == "" {
			if data.Len() > 0 {
				if err := c.handleData(ctx, data.String()); err != nil {
					c.logger.Error("failed to handle auth sync delivery", "error", err)
				}
				data.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
		}
	}
	return scanner.Err()
}

func (c *Client) handleData(ctx context.Context, raw string) error {
	var delivery Delivery
	if err := json.Unmarshal([]byte(raw), &delivery); err != nil {
		return err
	}
	if delivery.Type != "" && delivery.Type != "token.deliver" {
		return nil
	}
	if delivery.CredentialID == "" || delivery.Key == "" {
		return fmt.Errorf("auth sync delivery requires credential_id and key")
	}
	if err := c.secrets.Put(ctx, delivery.CredentialID, delivery.Key, delivery.Value); err != nil {
		return err
	}
	c.logger.Info("stored auth sync delivery", "delivery", delivery.DeliveryID, "credential", delivery.CredentialID, "key", delivery.Key)
	return nil
}
