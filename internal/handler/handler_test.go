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

func TestTokenReview_InvalidJSON(t *testing.T) {
	handler := NewTokenReviewHandler(nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader("not json"))
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
	handler := NewTokenReviewHandler(nil, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
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

func TestTokenReview_NotConfigured(t *testing.T) {
	handler := NewTokenReviewHandler(nil, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"test-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should return 200 with unauthenticated status (not 500)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp authv1.TokenReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status.Authenticated {
		t.Error("expected authenticated = false")
	}
	if resp.Status.Error != "server not configured" {
		t.Errorf("error = %q, want %q", resp.Status.Error, "server not configured")
	}
}

func TestTokenReview_ResponseFormat(t *testing.T) {
	handler := NewTokenReviewHandler(nil, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"invalid-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
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
