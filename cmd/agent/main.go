package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type RegisterRequest struct {
	Cluster     string      `json:"cluster"`
	Credentials Credentials `json:"credentials"`
}

type Credentials struct {
	Token  string `json:"token"`
	CACert string `json:"ca_cert"`
}

type RegisterResponse struct {
	Status    string `json:"status"`
	Cluster   string `json:"cluster"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
}

func main() {
	endpoint := mustEnv("MULTI_K8S_AUTH_ENDPOINT")
	clusterName := mustEnv("CLUSTER_NAME")
	refreshInterval := getEnvDuration("REFRESH_INTERVAL", 7*24*time.Hour)
	tokenPath := getEnv("TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	caPath := getEnv("CA_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

	log.Printf("Starting agent for cluster %s", clusterName)
	log.Printf("Endpoint: %s", endpoint)
	log.Printf("Refresh interval: %s", refreshInterval)

	// Initial registration with retries
	if err := registerWithRetry(endpoint, clusterName, tokenPath, caPath); err != nil {
		log.Fatalf("Initial registration failed: %v", err)
	}

	// Periodic refresh
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := registerWithRetry(endpoint, clusterName, tokenPath, caPath); err != nil {
			log.Printf("Registration failed: %v (will retry on next interval)", err)
		}
	}
}

func registerWithRetry(endpoint, clusterName, tokenPath, caPath string) error {
	maxRetries := 10
	baseDelay := 5 * time.Second
	maxDelay := 5 * time.Minute

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := register(endpoint, clusterName, tokenPath, caPath); err != nil {
			lastErr = err
			delay := baseDelay * time.Duration(1<<uint(i))
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("Registration attempt %d failed: %v, retrying in %s", i+1, err, delay)
			time.Sleep(delay)
			continue
		}
		return nil
	}
	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

func register(endpoint, clusterName, tokenPath, caPath string) error {
	// Read SA token
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("reading token: %w", err)
	}

	// Read CA cert
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}

	// Build request
	reqBody := RegisterRequest{
		Cluster: clusterName,
		Credentials: Credentials{
			Token:  string(token),
			CACert: base64.StdEncoding.EncodeToString(caCert),
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	// POST /register
	url := endpoint + "/register"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(token))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var result RegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed: %s - %s", result.Error, result.Message)
	}

	log.Printf("Registration successful for cluster %s", clusterName)
	return nil
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return value
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		log.Printf("Invalid duration for %s: %v, using default %s", key, err, fallback)
		return fallback
	}
	return d
}
