package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/takutakahashi/scia/internal/approval"
	"github.com/takutakahashi/scia/internal/config"
	"github.com/takutakahashi/scia/internal/oauth"
	"github.com/takutakahashi/scia/internal/proxy"
	"github.com/takutakahashi/scia/internal/secrets"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var configPath string
	var listenAddr string
	flag.StringVar(&configPath, "config", "configs/example.yaml", "path to YAML configuration")
	flag.StringVar(&listenAddr, "listen", "", "listen address override")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("starting scia", "version", version, "commit", commit, "date", date)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	provider := config.NewFileProvider(configPath, logger)
	store, err := config.NewStore(ctx, provider, logger)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	secretStore, err := secrets.NewSQLiteStore(ctx, store.Get().Server.Secrets.SQLitePath)
	if err != nil {
		logger.Error("failed to initialize secret store", "error", err)
		os.Exit(1)
	}
	defer secretStore.Close()

	cfg := store.Get()
	switch cfg.Server.Mode {
	case "proxy":
		runProxy(ctx, store, secretStore, listenAddr, logger)
	case "oauth":
		runOAuth(ctx, store, secretStore, listenAddr, logger)
	default:
		logger.Error("unsupported server mode", "mode", cfg.Server.Mode)
		os.Exit(1)
	}
	logger.Info("stopped scia")
}

func runProxy(ctx context.Context, store *config.Store, secretStore secrets.Store, listenAddr string, logger *slog.Logger) {
	if listenAddr == "" {
		listenAddr = store.Get().Server.Listen
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	approvals := approval.NewManager(store.Get().Server.ApprovalTimeout.Duration)
	handler, err := proxy.NewHandler(store, secretStore, approvals, logger)
	if err != nil {
		logger.Error("failed to initialize proxy", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("proxy listening", "addr", listenAddr)
		errCh <- server.ListenAndServe()
	}()

	waitAndShutdown(ctx, server, errCh, "proxy", logger)
}

func runOAuth(ctx context.Context, store *config.Store, secretStore secrets.Store, listenAddr string, logger *slog.Logger) {
	oauthServer := oauth.NewServer(store, secretStore, logger)
	if listenAddr == "" {
		listenAddr = oauthServer.ListenAddr()
	}
	oauthHTTPServer := &http.Server{
		Addr:              listenAddr,
		Handler:           oauthServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("oauth server listening", "addr", oauthHTTPServer.Addr, "url", oauth.NormalizeListenForDisplay(oauthHTTPServer.Addr))
		errCh <- oauthHTTPServer.ListenAndServe()
	}()

	waitAndShutdown(ctx, oauthHTTPServer, errCh, "oauth", logger)
}

func waitAndShutdown(ctx context.Context, server *http.Server, errCh <-chan error, name string, logger *slog.Logger) {
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "name", name, "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "name", name, "error", err)
		os.Exit(1)
	}
}
