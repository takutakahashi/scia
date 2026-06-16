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
	"github.com/takutakahashi/scia/internal/proxy"
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

	if listenAddr == "" {
		listenAddr = store.Get().Server.Listen
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	approvals := approval.NewManager(store.Get().Server.ApprovalTimeout.Duration)
	handler := proxy.NewHandler(store, approvals, logger)
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

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("stopped scia")
}
