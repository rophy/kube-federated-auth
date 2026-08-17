package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	kfadocs "github.com/rophy/kube-federated-auth"
	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	"github.com/rophy/kube-federated-auth/internal/server"
)

// Version is set at build time via -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	flag.Usage = func() {
		fmt.Fprint(os.Stdout, kfadocs.README)
	}

	configPath := flag.String("config", getEnv("CONFIG_PATH", "config/clusters.yaml"), "path to cluster config file (env: CONFIG_PATH)")
	port := flag.String("port", getEnv("PORT", "8080"), "server port (env: PORT)")
	secretName := flag.String("secret-name", getEnv("SECRET_NAME", "kube-federated-auth"), "name of credential secret (env: SECRET_NAME)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		if _, statErr := os.Stat(*configPath); statErr != nil {
			fmt.Fprintf(os.Stderr, "Config file not found: %s\n\n", *configPath)
			fmt.Fprintf(os.Stderr, "Usage:\n")
			fmt.Fprintf(os.Stderr, "  kube-federated-auth [flags]\n\n")
			fmt.Fprintf(os.Stderr, "Flags:\n")
			flag.CommandLine.SetOutput(os.Stderr)
			flag.PrintDefaults()
			fmt.Fprintf(os.Stderr, "\nRun with -help for full documentation.\n")
			os.Exit(1)
		}
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
