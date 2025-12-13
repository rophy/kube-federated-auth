package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests can run in two modes:
// 1. In-cluster: as a pod with SERVICE_URL and TOKEN_PATH env vars
// 2. Local: with kubectl port-forward (SERVICE_URL=http://localhost:8080)

var (
	serviceURL  = getEnv("SERVICE_URL", "http://localhost:8080")
	tokenPath   = getEnv("TOKEN_PATH", "")
	clusterName = getEnv("CLUSTER_NAME", "minikube")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func TestMain(m *testing.M) {
	if os.Getenv("E2E_TEST") != "true" {
		fmt.Println("Skipping e2e tests. Set E2E_TEST=true to run.")
		os.Exit(0)
	}

	// Wait for service to be ready
	waitForService(30 * time.Second)

	os.Exit(m.Run())
}

func TestHealth(t *testing.T) {
	resp, err := http.Get(serviceURL + "/health")
	if err != nil {
		t.Fatalf("failed to call /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestClusters(t *testing.T) {
	resp, err := http.Get(serviceURL + "/clusters")
	if err != nil {
		t.Fatalf("failed to call /clusters: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body struct {
		Clusters []string `json:"clusters"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	found := false
	for _, c := range body.Clusters {
		if c == clusterName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cluster %q not found in %v", clusterName, body.Clusters)
	}
}

func TestValidate_Success(t *testing.T) {
	token := getTestToken(t)

	reqBody, _ := json.Marshal(map[string]string{
		"cluster": clusterName,
		"token":   token,
	})

	resp, err := http.Post(serviceURL+"/validate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call /validate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Fatalf("status = %d, want %d, error: %v", resp.StatusCode, http.StatusOK, errResp)
	}

	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify expected fields
	if claims["cluster"] != clusterName {
		t.Errorf("cluster = %v, want %v", claims["cluster"], clusterName)
	}

	sub, ok := claims["sub"].(string)
	if !ok || !strings.HasPrefix(sub, "system:serviceaccount:") {
		t.Errorf("sub = %v, want system:serviceaccount:...", claims["sub"])
	}

	if claims["iss"] == nil {
		t.Error("iss is missing")
	}

	if claims["aud"] == nil {
		t.Error("aud is missing")
	}

	k8s, ok := claims["kubernetes.io"].(map[string]any)
	if !ok {
		t.Error("kubernetes.io claims missing")
	} else {
		if k8s["namespace"] == nil {
			t.Error("kubernetes.io.namespace is missing")
		}
		if k8s["serviceaccount"] == nil {
			t.Error("kubernetes.io.serviceaccount is missing")
		}
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	reqBody, _ := json.Marshal(map[string]string{
		"cluster": clusterName,
		"token":   "invalid.token.here",
	})

	resp, err := http.Post(serviceURL+"/validate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call /validate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	var errResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if errResp["error"] == "" {
		t.Error("error field is missing")
	}
}

func TestValidate_UnknownCluster(t *testing.T) {
	reqBody, _ := json.Marshal(map[string]string{
		"cluster": "unknown-cluster",
		"token":   "some-token",
	})

	resp, err := http.Post(serviceURL+"/validate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call /validate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var errResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if errResp["error"] != "cluster_not_found" {
		t.Errorf("error = %q, want %q", errResp["error"], "cluster_not_found")
	}
}

// getTestToken reads the token from TOKEN_PATH env var (in-cluster)
// or returns empty string to skip token-based tests (local without token)
func getTestToken(t *testing.T) string {
	t.Helper()

	if tokenPath == "" {
		t.Skip("TOKEN_PATH not set, skipping token validation test")
	}

	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("failed to read token from %s: %v", tokenPath, err)
	}

	return strings.TrimSpace(string(token))
}

// waitForService waits for the service to be ready
func waitForService(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(serviceURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			fmt.Printf("Service ready at %s\n", serviceURL)
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	fmt.Printf("Warning: service at %s may not be ready\n", serviceURL)
}
