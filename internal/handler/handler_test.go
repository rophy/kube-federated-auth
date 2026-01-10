package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authv1 "k8s.io/api/authentication/v1"

	"github.com/rophy/kube-federated-auth/internal/config"
)

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("status = %q, want %q", resp.Status, "ok")
	}
}

func TestClusters(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
			"cluster-b": {Issuer: "https://b.example.com", APIServer: "https://192.168.1.100:6443"},
		},
	}

	handler := NewClustersHandler(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/clusters", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp ClustersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp.Clusters) != 2 {
		t.Errorf("clusters count = %d, want %d", len(resp.Clusters), 2)
	}

	// Verify cluster info includes issuer and api_server
	for _, c := range resp.Clusters {
		if c.Name == "cluster-b" {
			if c.APIServer != "https://192.168.1.100:6443" {
				t.Errorf("cluster-b api_server = %q, want %q", c.APIServer, "https://192.168.1.100:6443")
			}
		}
		if c.Issuer == "" {
			t.Errorf("cluster %s issuer is empty", c.Name)
		}
	}
}

func TestExtractClusterFromHost(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"api.kube-fed.svc.cluster.local", "local"},
		{"api.kube-fed.svc.cluster.local:8080", "local"},
		{"api.kube-fed.svc", "local"},
		{"api.kube-fed", "local"},
		{"api.app1.kube-fed.svc.cluster.local", "app1"},
		{"api.app1.kube-fed.svc.cluster.local:443", "app1"},
		{"api.cluster-b.kube-fed.svc", "cluster-b"},
		{"api.my-cluster.kube-fed", "my-cluster"},
		{"invalid.host.name", ""},
		{"kube-fed.svc", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := extractClusterFromHost(tt.host)
			if got != tt.want {
				t.Errorf("extractClusterFromHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestTokenReview_InvalidJSON(t *testing.T) {
	handler := NewTokenReviewHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader("not json"))
	req.Host = "api.test-cluster.kube-fed.svc.cluster.local"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp authv1.TokenReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status.Authenticated {
		t.Error("expected authenticated = false")
	}
	if resp.Status.Error == "" {
		t.Error("expected error message")
	}
}

func TestTokenReview_MissingToken(t *testing.T) {
	handler := NewTokenReviewHandler(nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Host = "api.test-cluster.kube-fed.svc.cluster.local"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp authv1.TokenReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status.Authenticated {
		t.Error("expected authenticated = false")
	}
	if resp.Status.Error != "token is required" {
		t.Errorf("error = %q, want %q", resp.Status.Error, "token is required")
	}
}

func TestTokenReview_InvalidHost(t *testing.T) {
	handler := NewTokenReviewHandler(nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"test"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Host = "invalid.host.name"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp authv1.TokenReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status.Authenticated {
		t.Error("expected authenticated = false")
	}
	if !strings.Contains(resp.Status.Error, "unable to determine cluster") {
		t.Errorf("error = %q, expected to contain 'unable to determine cluster'", resp.Status.Error)
	}
}

func TestTokenReview_ResponseFormat(t *testing.T) {
	handler := NewTokenReviewHandler(nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"invalid-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Host = "api.test-cluster.kube-fed.svc.cluster.local"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	var resp authv1.TokenReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify response has correct TypeMeta
	if resp.APIVersion != "authentication.k8s.io/v1" {
		t.Errorf("apiVersion = %q, want %q", resp.APIVersion, "authentication.k8s.io/v1")
	}
	if resp.Kind != "TokenReview" {
		t.Errorf("kind = %q, want %q", resp.Kind, "TokenReview")
	}
}
