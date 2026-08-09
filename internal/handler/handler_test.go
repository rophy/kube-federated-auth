package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakekube "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	"github.com/rophy/kube-federated-auth/internal/oidc"
)

// mockVerifier implements TokenVerifier for testing.
type mockVerifier struct {
	// claims maps token -> Claims. If token is not in the map, Verify returns error.
	claims map[string]*oidc.Claims
}

func (m *mockVerifier) Verify(ctx context.Context, clusterName, rawToken string) (*oidc.Claims, error) {
	if c, ok := m.claims[rawToken]; ok {
		if c.Cluster == "" || c.Cluster == clusterName {
			return &oidc.Claims{
				Cluster:    clusterName,
				Issuer:     c.Issuer,
				Subject:    c.Subject,
				Kubernetes: c.Kubernetes,
			}, nil
		}
	}
	return nil, fmt.Errorf("token not valid for cluster %s", clusterName)
}

func TestHealth(t *testing.T) {
	handler := NewHealthHandler("v1.2.3", nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

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

	if resp.Version != "v1.2.3" {
		t.Errorf("version = %q, want %q", resp.Version, "v1.2.3")
	}
}

// mockStatusProvider implements ClusterStatusProvider for testing.
type mockStatusProvider struct {
	degraded map[string]string
}

func (m *mockStatusProvider) DegradedClusters() map[string]string {
	return m.degraded
}

func TestHealth_Degraded(t *testing.T) {
	provider := &mockStatusProvider{
		degraded: map[string]string{"cluster-a": "OIDC discovery failed"},
	}
	handler := NewHealthHandler("v1.0.0", provider)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp HealthResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != "degraded" {
		t.Errorf("status = %q, want %q", resp.Status, "degraded")
	}
	if resp.Clusters["cluster-a"] != "OIDC discovery failed" {
		t.Errorf("clusters[cluster-a] = %q, want %q", resp.Clusters["cluster-a"], "OIDC discovery failed")
	}
}

func TestTokenReview_500WhenDegraded_CallerAuth(t *testing.T) {
	cfg := &config.Config{
		AuthorizedClients: []string{"cluster-a/default/my-app"},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	verifier := &mockVerifier{claims: map[string]*oidc.Claims{}}
	provider := &mockStatusProvider{
		degraded: map[string]string{"cluster-a": "OIDC discovery failed"},
	}
	handler := NewTokenReviewHandler(verifier, cfg, nil, provider)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"some-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestTokenReview_500WhenDegraded_DetectCluster(t *testing.T) {
	verifier := &mockVerifier{
		claims: map[string]*oidc.Claims{
			"caller-token": {
				Subject: "system:serviceaccount:default:my-app",
				Kubernetes: map[string]any{
					"namespace":      "default",
					"serviceaccount": map[string]any{"name": "my-app"},
				},
			},
		},
	}
	cfg := &config.Config{
		AuthorizedClients: []string{"*/*/*"},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	provider := &mockStatusProvider{
		degraded: map[string]string{"cluster-b": "OIDC discovery failed"},
	}
	handler := NewTokenReviewHandler(verifier, cfg, nil, provider)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"unknown-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer caller-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestClusters(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
			"cluster-b": {Issuer: "https://b.example.com", APIServer: "https://cluster-b.example.com:6443"},
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
			if c.APIServer != "https://cluster-b.example.com:6443" {
				t.Errorf("cluster-b api_server = %q, want %q", c.APIServer, "https://cluster-b.example.com:6443")
			}
		}
		if c.Issuer == "" {
			t.Errorf("cluster %s issuer is empty", c.Name)
		}
	}
}

func TestTokenReview_InvalidJSON(t *testing.T) {
	handler := NewTokenReviewHandler(nil, nil, nil, nil)

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
	handler := NewTokenReviewHandler(nil, nil, nil, nil)

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
	handler := NewTokenReviewHandler(nil, nil, nil, nil)

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
	handler := NewTokenReviewHandler(nil, nil, nil, nil)

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

func TestExtraKeyClusterName(t *testing.T) {
	// Verify the constant follows Kubernetes naming convention
	expected := "authentication.kubernetes.io/cluster-name"
	if ExtraKeyClusterName != expected {
		t.Errorf("ExtraKeyClusterName = %q, want %q", ExtraKeyClusterName, expected)
	}
}

func TestTokenReview_NoAuthHeader_WithAuthorizedClients(t *testing.T) {
	cfg := &config.Config{
		AuthorizedClients: []string{"cluster-a/default/my-app"},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	verifier := &mockVerifier{claims: map[string]*oidc.Claims{}}
	handler := NewTokenReviewHandler(verifier, cfg, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"some-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestTokenReview_InvalidCallerToken(t *testing.T) {
	cfg := &config.Config{
		AuthorizedClients: []string{"cluster-a/default/my-app"},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	verifier := &mockVerifier{claims: map[string]*oidc.Claims{}}
	handler := NewTokenReviewHandler(verifier, cfg, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"some-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestTokenReview_ValidCallerButNotWhitelisted(t *testing.T) {
	cfg := &config.Config{
		AuthorizedClients: []string{"cluster-a/default/allowed-app"},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	verifier := &mockVerifier{
		claims: map[string]*oidc.Claims{
			"caller-token": {
				Subject: "system:serviceaccount:default:not-allowed",
				Kubernetes: map[string]any{
					"namespace": "default",
					"serviceaccount": map[string]any{
						"name": "not-allowed",
					},
				},
			},
		},
	}
	handler := NewTokenReviewHandler(verifier, cfg, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"some-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer caller-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestTokenReview_NoAuthorizedClients_SkipsAuth(t *testing.T) {
	// When authorized_clients is empty, auth should be skipped entirely
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	handler := NewTokenReviewHandler(nil, cfg, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"some-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	// No Authorization header - should still work because no authorized_clients configured
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should reach the "server not configured" path (nil verifier), not 401
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp authv1.TokenReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status.Error != "server not configured" {
		t.Errorf("error = %q, want %q", resp.Status.Error, "server not configured")
	}
}

func TestTokenReview_AuthHeaderNotBearer(t *testing.T) {
	cfg := &config.Config{
		AuthorizedClients: []string{"*/*/*"},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	handler := NewTokenReviewHandler(&mockVerifier{}, cfg, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"some-token"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestExtractIdentity(t *testing.T) {
	claims := &oidc.Claims{
		Kubernetes: map[string]any{
			"namespace": "kube-system",
			"serviceaccount": map[string]any{
				"name": "my-sa",
				"uid":  "abc-123",
			},
		},
	}

	ns, sa := extractIdentity(claims)
	if ns != "kube-system" {
		t.Errorf("namespace = %q, want %q", ns, "kube-system")
	}
	if sa != "my-sa" {
		t.Errorf("serviceAccount = %q, want %q", sa, "my-sa")
	}
}

func TestExtractIdentity_NilKubernetes(t *testing.T) {
	claims := &oidc.Claims{}
	ns, sa := extractIdentity(claims)
	if ns != "" || sa != "" {
		t.Errorf("expected empty, got ns=%q sa=%q", ns, sa)
	}
}

func TestExtractIdentity_MissingFields(t *testing.T) {
	claims := &oidc.Claims{
		Kubernetes: map[string]any{
			"namespace": "default",
			// no serviceaccount
		},
	}
	ns, sa := extractIdentity(claims)
	if ns != "default" {
		t.Errorf("namespace = %q, want %q", ns, "default")
	}
	if sa != "" {
		t.Errorf("serviceAccount = %q, want empty", sa)
	}
}

func TestTokenReviewHandler_CacheConstructedFromConfig(t *testing.T) {
	cfg := &config.Config{
		Cache: &config.CacheSettings{TTL: 60, MaxEntries: 1000},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {
				Issuer: "https://a.example.com",
				Cache:  &config.CacheSettings{TTL: 30, MaxEntries: 500},
			},
			"cluster-b": {
				Issuer: "https://b.example.com",
				// uses global cache
			},
		},
	}
	h := NewTokenReviewHandler(nil, cfg, nil, nil)

	if _, ok := h.caches["cluster-a"]; !ok {
		t.Error("expected cache for cluster-a")
	}
	if _, ok := h.caches["cluster-b"]; !ok {
		t.Error("expected cache for cluster-b (from global)")
	}
}

func TestTokenReviewHandler_CacheEnabledByDefault(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	h := NewTokenReviewHandler(nil, cfg, nil, nil)

	if _, ok := h.caches["cluster-a"]; !ok {
		t.Error("expected cache for cluster-a from defaults")
	}
}

// newTestCredStore creates a minimal credentials.Store for handler tests.
func newTestCredStore(t *testing.T) *credentials.Store {
	t.Helper()
	cfg := &config.Config{Clusters: map[string]config.ClusterConfig{}}
	store, err := credentials.NewStore(cfg, "test-secret")
	if err != nil {
		t.Fatalf("failed to create test cred store: %v", err)
	}
	return store
}

// makeTestJWT creates a minimal JWT with the given exp claim for testing.
func makeTestJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims, _ := json.Marshal(map[string]any{"exp": exp})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	return header + "." + payload + ".sig"
}

func TestExtractJWTExpiration(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    int64
		wantErr bool
	}{
		{
			name:  "valid JWT with exp",
			token: makeTestJWT(1700000000),
			want:  1700000000,
		},
		{
			name:  "not 3 parts returns 0",
			token: "only.two",
			want:  0,
		},
		{
			name:    "invalid base64",
			token:   "!!!.!!!.!!!",
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			token:   base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".payload.sig",
			wantErr: true,
		},
		{
			name:  "missing exp returns 0",
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"foo"}`)) + ".sig",
			want:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractJWTExpiration(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("extractJWTExpiration() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetTokenStatus(t *testing.T) {
	t.Run("nil creds", func(t *testing.T) {
		s := getTokenStatus(nil)
		if s.Status != "unknown" {
			t.Errorf("status = %q, want %q", s.Status, "unknown")
		}
	})
	t.Run("empty token", func(t *testing.T) {
		s := getTokenStatus(&credentials.Credentials{})
		if s.Status != "unknown" {
			t.Errorf("status = %q, want %q", s.Status, "unknown")
		}
	})
	t.Run("expired token", func(t *testing.T) {
		token := makeTestJWT(time.Now().Add(-1 * time.Hour).Unix())
		s := getTokenStatus(&credentials.Credentials{Token: token})
		if s.Status != "expired" {
			t.Errorf("status = %q, want %q", s.Status, "expired")
		}
	})
	t.Run("expiring soon", func(t *testing.T) {
		token := makeTestJWT(time.Now().Add(5 * time.Minute).Unix())
		s := getTokenStatus(&credentials.Credentials{Token: token})
		if s.Status != "expiring_soon" {
			t.Errorf("status = %q, want %q", s.Status, "expiring_soon")
		}
	})
	t.Run("valid token", func(t *testing.T) {
		token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
		s := getTokenStatus(&credentials.Credentials{Token: token})
		if s.Status != "valid" {
			t.Errorf("status = %q, want %q", s.Status, "valid")
		}
		if s.ExpiresAt == "" {
			t.Error("ExpiresAt should be set")
		}
		if s.ExpiresIn == "" {
			t.Error("ExpiresIn should be set")
		}
	})
}

func TestDetectCluster(t *testing.T) {
	// mockVerifier is cluster-aware: returns success only when claims.Cluster matches
	verifier := &mockVerifier{
		claims: map[string]*oidc.Claims{
			"token-for-a": {Cluster: "cluster-a", Subject: "sub-a"},
		},
	}
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
			"cluster-b": {Issuer: "https://b.example.com"},
		},
	}
	h := NewTokenReviewHandler(verifier, cfg, nil, nil)

	t.Run("token matches one cluster", func(t *testing.T) {
		cluster, claims, err := h.detectCluster(context.Background(), "token-for-a")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cluster != "cluster-a" {
			t.Errorf("cluster = %q, want %q", cluster, "cluster-a")
		}
		if claims == nil {
			t.Fatal("claims should not be nil")
		}
	})
	t.Run("token matches no cluster", func(t *testing.T) {
		_, _, err := h.detectCluster(context.Background(), "unknown-token")
		if err == nil {
			t.Error("expected error for unmatched token")
		}
	})
}

func TestTokenReview_TokenNotValidForAnyClusters(t *testing.T) {
	verifier := &mockVerifier{
		claims: map[string]*oidc.Claims{
			// Caller token valid for cluster-a
			"caller-token": {
				Subject: "system:serviceaccount:default:my-app",
				Kubernetes: map[string]any{
					"namespace":      "default",
					"serviceaccount": map[string]any{"name": "my-app"},
				},
			},
			// No review token registered → will fail all clusters
		},
	}
	cfg := &config.Config{
		AuthorizedClients: []string{"*/*/*"},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	handler := NewTokenReviewHandler(verifier, cfg, nil, nil)

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"review-token-invalid"}}`
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer caller-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp authv1.TokenReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status.Authenticated {
		t.Error("expected authenticated = false")
	}
	if !strings.Contains(resp.Status.Error, "not valid for any configured cluster") {
		t.Errorf("error = %q, want to contain 'not valid for any configured cluster'", resp.Status.Error)
	}
}

func TestBuildRESTConfig(t *testing.T) {
	t.Run("remote cluster with credentials", func(t *testing.T) {
		store := newTestCredStore(t)
		store.SetToken("remote", "my-token")
		// Set CA via the exported method that exists - use the test helper
		store.SetCACert("remote", []byte("ca-data"))

		h := NewTokenReviewHandler(nil, nil, store, nil)
		cfg := config.ClusterConfig{
			APIServer: "https://remote-api:6443",
			Issuer:    "https://issuer.example.com",
		}

		rc, err := h.buildRESTConfig("remote", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.Host != "https://remote-api:6443" {
			t.Errorf("Host = %q, want %q", rc.Host, "https://remote-api:6443")
		}
		if rc.BearerToken != "my-token" {
			t.Errorf("BearerToken = %q, want %q", rc.BearerToken, "my-token")
		}
		if string(rc.TLSClientConfig.CAData) != "ca-data" {
			t.Errorf("CAData = %q, want %q", string(rc.TLSClientConfig.CAData), "ca-data")
		}
	})
	t.Run("remote no credentials", func(t *testing.T) {
		store := newTestCredStore(t)
		h := NewTokenReviewHandler(nil, nil, store, nil)
		cfg := config.ClusterConfig{
			APIServer: "https://remote-api:6443",
		}

		rc, err := h.buildRESTConfig("remote", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.BearerToken != "" {
			t.Errorf("BearerToken = %q, want empty", rc.BearerToken)
		}
	})
	t.Run("qps and burst applied", func(t *testing.T) {
		store := newTestCredStore(t)
		store.SetToken("remote", "my-token")
		h := NewTokenReviewHandler(nil, nil, store, nil)
		cfg := config.ClusterConfig{
			APIServer: "https://remote-api:6443",
			QPS:       100,
			Burst:     200,
		}

		rc, err := h.buildRESTConfig("remote", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.QPS != 100 {
			t.Errorf("QPS = %v, want 100", rc.QPS)
		}
		if rc.Burst != 200 {
			t.Errorf("Burst = %d, want 200", rc.Burst)
		}
	})
	t.Run("qps and burst default to zero when unset", func(t *testing.T) {
		store := newTestCredStore(t)
		h := NewTokenReviewHandler(nil, nil, store, nil)
		cfg := config.ClusterConfig{
			APIServer: "https://remote-api:6443",
		}

		rc, err := h.buildRESTConfig("remote", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rc.QPS != 0 {
			t.Errorf("QPS = %v, want 0", rc.QPS)
		}
		if rc.Burst != 0 {
			t.Errorf("Burst = %d, want 0", rc.Burst)
		}
	})
	t.Run("no api_server falls back to issuer", func(t *testing.T) {
		h := NewTokenReviewHandler(nil, nil, nil, nil)
		cfg := config.ClusterConfig{
			Issuer: "https://issuer.example.com",
		}

		rc, err := h.buildRESTConfig("local", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// When not in-cluster, falls back to issuer as host
		if rc.Host != "https://issuer.example.com" {
			t.Errorf("Host = %q, want %q", rc.Host, "https://issuer.example.com")
		}
	})
}

// newFakeClientWithCounter creates a fake K8s client that counts TokenReview calls
// and adds an optional delay to simulate latency.
func newFakeClientWithCounter(callCount *atomic.Int32, delay time.Duration, authenticated bool) *fakekube.Clientset {
	client := fakekube.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		callCount.Add(1)
		if delay > 0 {
			time.Sleep(delay)
		}
		return true, &authv1.TokenReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authentication.k8s.io/v1",
				Kind:       "TokenReview",
			},
			Status: authv1.TokenReviewStatus{
				Authenticated: authenticated,
				User: authv1.UserInfo{
					Username: "system:serviceaccount:default:test-sa",
				},
			},
		}, nil
	})
	return client
}

func TestSingleflight_DeduplicatesConcurrentRequests(t *testing.T) {
	var callCount atomic.Int32
	fakeClient := newFakeClientWithCounter(&callCount, 100*time.Millisecond, true)

	cfg := &config.Config{
		Cache: &config.CacheSettings{TTL: 60, MaxEntries: 1000},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	verifier := &mockVerifier{
		claims: map[string]*oidc.Claims{
			"test-token": {
				Subject: "system:serviceaccount:default:test-sa",
				Kubernetes: map[string]any{
					"namespace":      "default",
					"serviceaccount": map[string]any{"name": "test-sa"},
				},
			},
		},
	}

	h := NewTokenReviewHandler(verifier, cfg, nil, nil)
	h.clients["cluster-a"] = fakeClient

	const concurrency = 10
	var wg sync.WaitGroup
	results := make([]*authv1.TokenReview, concurrency)

	for i := range concurrency {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"test-token"}}`
			req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			var resp authv1.TokenReview
			json.Unmarshal(w.Body.Bytes(), &resp)
			results[idx] = &resp
		}(i)
	}
	wg.Wait()

	if count := callCount.Load(); count != 1 {
		t.Errorf("expected 1 upstream call, got %d", count)
	}

	for i, resp := range results {
		if !resp.Status.Authenticated {
			t.Errorf("request %d: expected authenticated=true", i)
		}
	}
}

func TestNegativeCaching_UnauthenticatedResultsCached(t *testing.T) {
	var callCount atomic.Int32
	fakeClient := newFakeClientWithCounter(&callCount, 0, false)

	cfg := &config.Config{
		Cache: &config.CacheSettings{TTL: 60, NegativeTTL: 30, MaxEntries: 1000},
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
		},
	}
	verifier := &mockVerifier{
		claims: map[string]*oidc.Claims{
			"bad-token": {
				Subject: "system:serviceaccount:default:bad-sa",
				Kubernetes: map[string]any{
					"namespace":      "default",
					"serviceaccount": map[string]any{"name": "bad-sa"},
				},
			},
		},
	}

	h := NewTokenReviewHandler(verifier, cfg, nil, nil)
	h.clients["cluster-a"] = fakeClient

	body := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"bad-token"}}`

	// First request: cache miss, calls upstream
	req := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var resp authv1.TokenReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status.Authenticated {
		t.Error("first request: expected authenticated=false")
	}
	if callCount.Load() != 1 {
		t.Errorf("first request: expected 1 upstream call, got %d", callCount.Load())
	}

	// Second request: should be served from negative cache
	req = httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(body))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status.Authenticated {
		t.Error("second request: expected authenticated=false")
	}
	if callCount.Load() != 1 {
		t.Errorf("second request: expected still 1 upstream call (cached), got %d", callCount.Load())
	}
}
