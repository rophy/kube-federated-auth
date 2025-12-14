package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rophy/multi-k8s-auth/internal/config"
	"github.com/rophy/multi-k8s-auth/internal/credentials"
	"github.com/rophy/multi-k8s-auth/internal/server"
)

func main() {
	configPath := flag.String("config", getEnv("CONFIG_PATH", "config/clusters.yaml"), "path to cluster config file")
	port := flag.String("port", getEnv("PORT", "8080"), "server port")
	namespace := flag.String("namespace", getEnv("NAMESPACE", "multi-k8s-auth"), "namespace for credential secret")
	secretName := flag.String("secret-name", getEnv("SECRET_NAME", "multi-k8s-auth"), "name of credential secret")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Loaded %d cluster(s): %v", len(cfg.Clusters), cfg.ClusterNames())

	credStore, err := credentials.NewStore(*namespace, *secretName)
	if err != nil {
		log.Fatalf("Failed to create credential store: %v", err)
	}

	// Load bootstrap credentials from files for clusters with renewal enabled
	for clusterName, clusterCfg := range cfg.Clusters {
		if clusterCfg.TokenPath != "" && clusterCfg.CACert != "" {
			if err := credStore.LoadFromFiles(clusterName, clusterCfg.TokenPath, clusterCfg.CACert); err != nil {
				log.Printf("Warning: could not load bootstrap credentials for %s: %v", clusterName, err)
			}
		}
	}

	srv := server.New(cfg, credStore)

	// Start credential renewal if any clusters have renewal enabled
	renewalClusters := cfg.GetRenewalClusters()
	if len(renewalClusters) > 0 {
		log.Printf("Starting credential renewal for clusters: %v", renewalClusters)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		renewer := credentials.NewRenewer(cfg, credStore, srv.Verifier)
		renewer.Start(ctx)

		// Handle shutdown gracefully
		go func() {
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			<-sigCh
			log.Println("Shutting down...")
			cancel()
		}()
	}

	addr := ":" + *port
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, srv.Handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
