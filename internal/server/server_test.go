package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
)

func newOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": issuer + "/openid/v1/jwks",
		})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})
	ts := httptest.NewServer(mux)
	issuer = ts.URL
	t.Cleanup(ts.Close)
	return ts
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	ts := newOIDCServer(t)
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: ts.URL},
		},
	}
	store, err := credentials.NewStore(cfg, "test-secret")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return New(cfg, store, "v-test")
}

func TestNewWiresRoutes(t *testing.T) {
	srv := newTestServer(t)

	if srv.Verifier == nil {
		t.Fatal("expected verifier to be set")
	}
	if len(srv.Verifier.DegradedClusters()) != 0 {
		t.Fatalf("expected no degraded clusters, got %v", srv.Verifier.DegradedClusters())
	}

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantBody   string
	}{
		{"health", "GET", "/health", "", http.StatusOK, `"status":"ok"`},
		{"clusters", "GET", "/clusters", "", http.StatusOK, `"name":"cluster-a"`},
		{"metrics", "GET", "/metrics", "", http.StatusOK, "go_goroutines"},
		{"tokenreview bad body", "POST", "/apis/authentication.k8s.io/v1/tokenreviews", "not-json", http.StatusBadRequest, ""},
		{"tokenreview wrong method", "GET", "/apis/authentication.k8s.io/v1/tokenreviews", "", http.StatusMethodNotAllowed, ""},
		{"unknown path", "GET", "/nope", "", http.StatusNotFound, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not contain %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestNewHealthReportsDegradedCluster(t *testing.T) {
	// metrics.New registers on the default registerer; swap it so this second
	// New() call does not collide with TestNewWiresRoutes.
	orig := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	t.Cleanup(func() { prometheus.DefaultRegisterer = orig })

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"broken": {Issuer: "http://127.0.0.1:1"},
		},
	}
	store, err := credentials.NewStore(cfg, "test-secret")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	srv := New(cfg, store, "v-test")

	if _, ok := srv.Verifier.DegradedClusters()["broken"]; !ok {
		t.Fatal("expected broken cluster to be degraded")
	}

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"degraded"`) {
		t.Fatalf("expected degraded status, got %s", rec.Body.String())
	}
}
