package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rophy/multi-k8s-auth/internal/config"
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

func TestValidate_InvalidJSON(t *testing.T) {
	handler := NewValidateHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", resp.Error, "invalid_request")
	}
}

func TestValidate_MissingCluster(t *testing.T) {
	handler := NewValidateHandler(nil)

	body := `{"token": "some-token"}`
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", resp.Error, "invalid_request")
	}
}

func TestValidate_MissingToken(t *testing.T) {
	handler := NewValidateHandler(nil)

	body := `{"cluster": "some-cluster"}`
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", resp.Error, "invalid_request")
	}
}

func TestMapError(t *testing.T) {
	tests := []struct {
		name       string
		errMsg     string
		wantCode   int
		wantError  string
	}{
		{
			name:      "cluster not found",
			errMsg:    "cluster not found: unknown",
			wantCode:  http.StatusBadRequest,
			wantError: "cluster_not_found",
		},
		{
			name:      "token expired",
			errMsg:    "token is expired",
			wantCode:  http.StatusUnauthorized,
			wantError: "token_expired",
		},
		{
			name:      "invalid signature",
			errMsg:    "failed to verify signature",
			wantCode:  http.StatusUnauthorized,
			wantError: "invalid_signature",
		},
		{
			name:      "oidc discovery failed",
			errMsg:    "creating OIDC provider: connection refused",
			wantCode:  http.StatusInternalServerError,
			wantError: "oidc_discovery_failed",
		},
		{
			name:      "jwks fetch failed",
			errMsg:    "fetching JWKS: timeout",
			wantCode:  http.StatusInternalServerError,
			wantError: "jwks_fetch_failed",
		},
		{
			name:      "generic error",
			errMsg:    "something went wrong",
			wantCode:  http.StatusUnauthorized,
			wantError: "invalid_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, resp := mapError(errFromString(tt.errMsg))

			if code != tt.wantCode {
				t.Errorf("code = %d, want %d", code, tt.wantCode)
			}
			if resp.Error != tt.wantError {
				t.Errorf("error = %q, want %q", resp.Error, tt.wantError)
			}
		})
	}
}

type stringError string

func (e stringError) Error() string { return string(e) }

func errFromString(s string) error {
	return stringError(s)
}
