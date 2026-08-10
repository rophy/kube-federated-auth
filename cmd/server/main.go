package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	"github.com/rophy/kube-federated-auth/internal/server"
)

// Version is set at build time via -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	configPath := flag.String("config", getEnv("CONFIG_PATH", "config/clusters.yaml"), "path to cluster config file")
	port := flag.String("port", getEnv("PORT", "8080"), "server port")
	secretName := flag.String("secret-name", getEnv("SECRET_NAME", "kube-federated-auth"), "name of credential secret")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Reconfigure logger with config-driven log level
	logLevel := cfg.GetLogLevel()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	slog.Info("config loaded", "clusters", cfg.ClusterNames(), "count", len(cfg.Clusters), "log_level", cfg.LogLevel)

	credStore, err := credentials.NewStore(cfg, *secretName)
	if err != nil {
		slog.Error("failed to create credential store", "error", err)
		os.Exit(1)
	}

	slog.Info("starting server", "version", Version, "addr", ":"+*port)
	srv := server.New(cfg, credStore, Version)

	// Start credential renewal and handle shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	credStore.Start(ctx, srv.Verifier)

	if err := listenAndServe(ctx, ":"+*port, srv.Handler); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func listenAndServe(ctx context.Context, addr string, handler http.Handler) error {
	httpSrv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown deadline exceeded, forcing close", "error", err)
			httpSrv.Close()
		}
		close(shutdownDone)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	<-shutdownDone
	return nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
