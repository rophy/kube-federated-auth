package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/rophy/multi-k8s-auth/internal/config"
	"github.com/rophy/multi-k8s-auth/internal/credentials"
	"github.com/rophy/multi-k8s-auth/internal/server"
)

func main() {
	configPath := flag.String("config", getEnv("CONFIG_PATH", "config/clusters.yaml"), "path to cluster config file")
	port := flag.String("port", getEnv("PORT", "8080"), "server port")
	namespace := flag.String("namespace", getEnv("NAMESPACE", "multi-k8s-auth"), "namespace for credential secret")
	secretName := flag.String("secret-name", getEnv("SECRET_NAME", "multi-k8s-auth-credentials"), "name of credential secret")
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

	srv := server.New(cfg, credStore)

	addr := ":" + *port
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
