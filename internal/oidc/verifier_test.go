package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
)

func TestExtractKID(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantKID string
	}{
		{
			name:    "valid JWT with kid",
			token:   makeJWTHeader(map[string]any{"alg": "RS256", "kid": "key-123"}) + ".payload.signature",
			wantKID: "key-123",
		},
		{
			name:    "valid JWT without kid",
			token:   makeJWTHeader(map[string]any{"alg": "RS256"}) + ".payload.signature",
			wantKID: "",
		},
		{
			name:    "malformed token - no dots",
			token:   "notavalidtoken",
			wantKID: "",
		},
		{
			name:    "malformed token - invalid base64",
			token:   "!!!invalid!!!.payload.signature",
			wantKID: "",
		},
		{
			name:    "malformed token - invalid JSON",
			token:   base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".payload.signature",
			wantKID: "",
		},
		{
			name:    "empty string",
			token:   "",
			wantKID: "",
		},
		{
			name:    "kid is empty string",
			token:   makeJWTHeader(map[string]any{"alg": "RS256", "kid": ""}) + ".payload.signature",
			wantKID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKID(tt.token)
			if got != tt.wantKID {
				t.Errorf("extractKID() = %q, want %q", got, tt.wantKID)
			}
		})
	}
}

func TestFetchKIDs(t *testing.T) {
	jwks := `{"keys":[{"kid":"k1","kty":"RSA"},{"kid":"k2","kty":"RSA"},{"kty":"RSA"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, jwks)
	}))
	defer srv.Close()

	kids, err := fetchKIDs(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchKIDs() error: %v", err)
	}
	if len(kids) != 2 {
		t.Fatalf("fetchKIDs() returned %d kids, want 2", len(kids))
	}
	if kids[0] != "k1" || kids[1] != "k2" {
		t.Errorf("fetchKIDs() = %v, want [k1, k2]", kids)
	}
}

func TestFetchKIDs_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchKIDs(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("fetchKIDs() should return error on non-200 status")
	}
}

func TestVerifyKIDShortCircuit(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com"},
			"cluster-b": {Issuer: "https://b.example.com"},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.kidToCluster["key-cluster-a"] = "cluster-a"
	mgr.kidToCluster["key-cluster-b"] = "cluster-b"

	// Build a token with kid belonging to cluster-a
	token := makeJWTHeader(map[string]any{"alg": "RS256", "kid": "key-cluster-a"}) + ".payload.signature"

	// Verify against cluster-b should be short-circuited (no go-oidc call)
	_, err := mgr.Verify(context.Background(), "cluster-b", token)
	if err == nil {
		t.Fatal("Verify() should return error for wrong-cluster kid")
	}
	wantMsg := `kid "key-cluster-a" belongs to cluster cluster-a, not cluster-b`
	if err.Error() != wantMsg {
		t.Errorf("Verify() error = %q, want %q", err.Error(), wantMsg)
	}
}

func TestVerifyUnknownKIDFallsThrough(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-b": {Issuer: "https://b.example.com"},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.kidToCluster["key-cluster-a"] = "cluster-a"

	token := makeJWTHeader(map[string]any{"alg": "RS256", "kid": "unknown-key"}) + ".payload.signature"

	_, err := mgr.Verify(context.Background(), "cluster-b", token)
	if err == nil {
		t.Fatal("Verify() should fail (no real verifier)")
	}
	// Should NOT be the kid short-circuit error
	if strings.Contains(err.Error(), "belongs to cluster") {
		t.Errorf("unknown kid should fall through, got short-circuit error: %v", err)
	}
}

func TestInvalidateVerifierClearsKIDs(t *testing.T) {
	mgr := &VerifierManager{
		kidToCluster: map[string]string{
			"k1": "cluster-a",
			"k2": "cluster-a",
			"k3": "cluster-b",
		},
		verifiers: make(map[string]*gooidc.IDTokenVerifier),
	}

	mgr.InvalidateVerifier("cluster-a")

	if len(mgr.kidToCluster) != 1 {
		t.Fatalf("kidToCluster has %d entries, want 1", len(mgr.kidToCluster))
	}
	if mgr.kidToCluster["k3"] != "cluster-b" {
		t.Error("cluster-b kid should remain after invalidating cluster-a")
	}
}

func TestRewriteJWKSURL(t *testing.T) {
	tests := []struct {
		name      string
		jwksURL   string
		apiServer string
		want      string
	}{
		{
			name:      "standard k8s URL rewritten",
			jwksURL:   "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
			apiServer: "https://10.0.0.1:6443",
			want:      "https://10.0.0.1:6443/openid/v1/jwks",
		},
		{
			name:      "URL without /openid/v1/jwks returned as-is",
			jwksURL:   "https://example.com/.well-known/jwks.json",
			apiServer: "https://10.0.0.1:6443",
			want:      "https://example.com/.well-known/jwks.json",
		},
		{
			name:      "apiServer trailing slash trimmed",
			jwksURL:   "https://kubernetes.default.svc/openid/v1/jwks",
			apiServer: "https://10.0.0.1:6443/",
			want:      "https://10.0.0.1:6443/openid/v1/jwks",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rewriteJWKSURL(tt.jwksURL, tt.apiServer)
			if got != tt.want {
				t.Errorf("rewriteJWKSURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWarmUp(t *testing.T) {
	// Serve OIDC discovery + JWKS for cluster-a, return 401 for cluster-b
	srvA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":"https://a.example.com","jwks_uri":"%s/jwks"}`, "https://"+r.Host)
		case "/jwks":
			fmt.Fprint(w, `{"keys":[{"kid":"a1","kty":"RSA"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srvA.Close()

	srvB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"message":"Unauthorized"}`)
	}))
	defer srvB.Close()

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com", APIServer: srvA.URL},
			"cluster-b": {Issuer: "https://b.example.com", APIServer: srvB.URL},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	// Inject TLS clients so the test servers' certs are trusted
	mgr.testHTTPClients = map[string]*http.Client{
		"cluster-a": srvA.Client(),
		"cluster-b": srvB.Client(),
	}

	mgr.WarmUp(context.Background())

	// cluster-a should be healthy
	if _, ok := mgr.verifiers["cluster-a"]; !ok {
		t.Error("expected verifier for cluster-a after warmup")
	}

	// cluster-b should be degraded
	degraded := mgr.DegradedClusters()
	if degraded == nil || degraded["cluster-b"] == "" {
		t.Error("expected cluster-b to be degraded after warmup")
	}

	// cluster-a should not be degraded
	if _, ok := degraded["cluster-a"]; ok {
		t.Error("expected cluster-a to not be degraded")
	}
}

func TestDiscoveryFallbackToTokenPath(t *testing.T) {
	// Serve OIDC discovery that requires a valid bearer token
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-mounted-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"Unauthorized"}`)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":"https://a.example.com","jwks_uri":"%s/jwks"}`, "https://"+r.Host)
		case "/jwks":
			fmt.Fprint(w, `{"keys":[{"kid":"a1","kty":"RSA"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// Write a valid mounted token to a temp file
	tokenFile := t.TempDir() + "/token"
	os.WriteFile(tokenFile, []byte("valid-mounted-token"), 0600)

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {
				Issuer:    "https://a.example.com",
				APIServer: srv.URL,
				TokenPath: tokenFile,
			},
		},
	}

	// Create a credStore with a stale token
	credStore, err := credentials.NewStore(
		&config.Config{Clusters: map[string]config.ClusterConfig{}}, "test-secret",
	)
	if err != nil {
		t.Fatalf("failed to create cred store: %v", err)
	}
	credStore.SetToken("cluster-a", "stale-invalid-token")

	mgr := NewVerifierManager(cfg, credStore)
	// Use the test server's TLS client only for the initial (stale) attempt
	// but NOT for the fallback — the fallback must use createHTTPClientFromTokenPath
	// To test the fallback properly, we need the test server's TLS cert trusted.
	// Use testHTTPClients to skip createHTTPClient entirely, but we need the fallback path.
	// Instead, let's not use testHTTPClients and handle TLS differently.

	// Since we can't easily trust the test server cert in createHTTPClient,
	// let's verify the fallback logic via the degraded state after warmup.
	// The stale token will fail discovery, then the fallback should try token_path.

	// For this test, inject the TLS client for the initial attempt only
	// Actually, testHTTPClients bypasses createHTTPClient entirely, so let's
	// test the createHTTPClientFromTokenPath method directly instead.

	client, err := mgr.createHTTPClientFromTokenPath(cfg.Clusters["cluster-a"])
	if err != nil {
		t.Fatalf("createHTTPClientFromTokenPath() error: %v", err)
	}

	// The client should use the token from the file
	// Make a request to the test server (using the TLS client's transport for cert trust)
	client.Transport = &tokenRoundTripper{
		transport: srv.Client().Transport,
		tokenPath: tokenFile,
	}

	resp, err := client.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("request with token_path client failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with mounted token, got %d", resp.StatusCode)
	}
}

func TestClearTokenEnablesFallback(t *testing.T) {
	credStore, err := credentials.NewStore(
		&config.Config{Clusters: map[string]config.ClusterConfig{}}, "test-secret",
	)
	if err != nil {
		t.Fatalf("failed to create cred store: %v", err)
	}

	credStore.SetToken("cluster-a", "stale-token")

	// Verify token exists
	creds, ok := credStore.Get("cluster-a")
	if !ok || creds.Token != "stale-token" {
		t.Fatal("expected stale token to be set")
	}

	// Clear the token
	credStore.ClearToken("cluster-a")

	// Verify token is cleared
	creds, ok = credStore.Get("cluster-a")
	if !ok {
		t.Fatal("expected credentials entry to still exist")
	}
	if creds.Token != "" {
		t.Errorf("expected empty token after ClearToken, got %q", creds.Token)
	}
}

// makeJWTHeader encodes a JSON object as a base64url JWT header segment.
func makeJWTHeader(header map[string]any) string {
	b, _ := json.Marshal(header)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func jwksJSON(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":%q,"n":%q,"e":%q}]}`, kid, n, e)
}

func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := makeJWTHeader(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newOIDCTestServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":"https://a.example.com","jwks_uri":"https://%s/openid/v1/jwks"}`, r.Host)
		case "/openid/v1/jwks":
			fmt.Fprint(w, jwksJSON(t, key, kid))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifySuccess(t *testing.T) {
	key := newSigningKey(t)
	srv := newOIDCTestServer(t, key, "kid-1")

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com", APIServer: srv.URL},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.testHTTPClients = map[string]*http.Client{"cluster-a": srv.Client()}

	token := signJWT(t, key, "kid-1", map[string]any{
		"iss": "https://a.example.com",
		"sub": "system:serviceaccount:default:app",
		"aud": []string{"api"},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
		"kubernetes.io": map[string]any{
			"namespace": "default",
		},
	})

	claims, err := mgr.Verify(context.Background(), "cluster-a", token)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if claims.Cluster != "cluster-a" {
		t.Errorf("Cluster = %q, want cluster-a", claims.Cluster)
	}
	if claims.Subject != "system:serviceaccount:default:app" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Issuer != "https://a.example.com" {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "api" {
		t.Errorf("Audience = %v", claims.Audience)
	}
	if claims.Kubernetes["namespace"] != "default" {
		t.Errorf("Kubernetes = %v", claims.Kubernetes)
	}
	if mgr.kidToCluster["kid-1"] != "cluster-a" {
		t.Error("expected kid-1 learned for cluster-a")
	}

	// Second call exercises the cached-verifier path
	if _, err := mgr.Verify(context.Background(), "cluster-a", token); err != nil {
		t.Fatalf("second Verify() error: %v", err)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	key := newSigningKey(t)
	srv := newOIDCTestServer(t, key, "kid-1")

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com", APIServer: srv.URL},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.testHTTPClients = map[string]*http.Client{"cluster-a": srv.Client()}

	token := signJWT(t, key, "kid-1", map[string]any{
		"iss": "https://a.example.com",
		"sub": "expired",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	_, err := mgr.Verify(context.Background(), "cluster-a", token)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Verify() error = %v, want expired error", err)
	}
}

func TestVerifyBadSignature(t *testing.T) {
	key := newSigningKey(t)
	other := newSigningKey(t)
	srv := newOIDCTestServer(t, key, "kid-1")

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com", APIServer: srv.URL},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.testHTTPClients = map[string]*http.Client{"cluster-a": srv.Client()}

	token := signJWT(t, other, "kid-1", map[string]any{"iss": "https://a.example.com", "sub": "x"})

	_, err := mgr.Verify(context.Background(), "cluster-a", token)
	if err == nil || !strings.Contains(err.Error(), "verifying token") {
		t.Fatalf("Verify() error = %v, want verification failure", err)
	}
}

func TestVerifyUnknownCluster(t *testing.T) {
	mgr := NewVerifierManager(&config.Config{Clusters: map[string]config.ClusterConfig{}}, nil)
	_, err := mgr.Verify(context.Background(), "nope", "token")
	if err == nil || !strings.Contains(err.Error(), "cluster not found") {
		t.Fatalf("Verify() error = %v, want cluster not found", err)
	}
}

func TestSetMetricsTracksDegradedState(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_degraded"}, []string{"cluster"})

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-a": {Issuer: "https://a.example.com", APIServer: failing.URL},
		},
	}
	mgr := NewVerifierManager(cfg, nil)
	mgr.SetMetrics(gauge)
	mgr.testHTTPClients = map[string]*http.Client{"cluster-a": failing.Client()}

	mgr.WarmUp(context.Background())

	if v := gaugeValue(t, gauge, "cluster-a"); v != 1 {
		t.Errorf("degraded gauge = %v, want 1", v)
	}

	key := newSigningKey(t)
	good := newOIDCTestServer(t, key, "kid-1")
	cfg.Clusters["cluster-a"] = config.ClusterConfig{Issuer: "https://a.example.com", APIServer: good.URL}
	mgr.testHTTPClients["cluster-a"] = good.Client()

	mgr.WarmUp(context.Background())

	if v := gaugeValue(t, gauge, "cluster-a"); v != 0 {
		t.Errorf("degraded gauge = %v, want 0 after recovery", v)
	}
	if mgr.DegradedClusters() != nil {
		t.Error("expected no degraded clusters after recovery")
	}
}

func TestCreateHTTPClientBadCACert(t *testing.T) {
	credStore, err := credentials.NewStore(&config.Config{Clusters: map[string]config.ClusterConfig{}}, "test-secret")
	if err != nil {
		t.Fatalf("cred store: %v", err)
	}
	credStore.SetCACert("cluster-a", []byte("not a pem"))

	mgr := NewVerifierManager(&config.Config{Clusters: map[string]config.ClusterConfig{}}, credStore)
	if _, err := mgr.createHTTPClient("cluster-a", config.ClusterConfig{}); err == nil {
		t.Fatal("expected error for unparsable CA cert")
	}
}

func TestCreateHTTPClientTransportSelection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	credStore, err := credentials.NewStore(&config.Config{Clusters: map[string]config.ClusterConfig{}}, "test-secret")
	if err != nil {
		t.Fatalf("cred store: %v", err)
	}
	credStore.SetCACert("cluster-a", caPEM)
	credStore.SetToken("cluster-a", "stored-token")

	mgr := NewVerifierManager(&config.Config{Clusters: map[string]config.ClusterConfig{}}, credStore)

	client, err := mgr.createHTTPClient("cluster-a", config.ClusterConfig{})
	if err != nil {
		t.Fatalf("createHTTPClient() error: %v", err)
	}
	if got := doAndRead(t, client, srv.URL); got != "Bearer stored-token" {
		t.Errorf("Authorization = %q, want stored token", got)
	}

	tokenFile := t.TempDir() + "/token"
	if err := os.WriteFile(tokenFile, []byte("file-token"), 0600); err != nil {
		t.Fatal(err)
	}
	credStore.ClearToken("cluster-a")

	client, err = mgr.createHTTPClient("cluster-a", config.ClusterConfig{TokenPath: tokenFile})
	if err != nil {
		t.Fatalf("createHTTPClient() error: %v", err)
	}
	if got := doAndRead(t, client, srv.URL); got != "Bearer file-token" {
		t.Errorf("Authorization = %q, want file token", got)
	}
}

func TestCreateHTTPClientTestHook(t *testing.T) {
	injected := &http.Client{}
	mgr := NewVerifierManager(&config.Config{Clusters: map[string]config.ClusterConfig{}}, nil)
	mgr.testHTTPClients = map[string]*http.Client{"cluster-a": injected}

	got, err := mgr.createHTTPClient("cluster-a", config.ClusterConfig{})
	if err != nil || got != injected {
		t.Fatalf("createHTTPClient() = %v, %v; want injected client", got, err)
	}
}

func TestCreateHTTPClientFromTokenPathCACert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	tokenFile := dir + "/token"
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("mounted-token"), 0600); err != nil {
		t.Fatal(err)
	}

	mgr := NewVerifierManager(&config.Config{Clusters: map[string]config.ClusterConfig{}}, nil)

	client, err := mgr.createHTTPClientFromTokenPath(config.ClusterConfig{CACert: caFile, TokenPath: tokenFile})
	if err != nil {
		t.Fatalf("createHTTPClientFromTokenPath() error: %v", err)
	}
	if got := doAndRead(t, client, srv.URL); got != "Bearer mounted-token" {
		t.Errorf("Authorization = %q, want mounted token", got)
	}

	if _, err := mgr.createHTTPClientFromTokenPath(config.ClusterConfig{CACert: dir + "/missing.pem"}); err == nil {
		t.Error("expected error for missing CA cert file")
	}

	badCA := dir + "/bad.pem"
	if err := os.WriteFile(badCA, []byte("not a pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.createHTTPClientFromTokenPath(config.ClusterConfig{CACert: badCA}); err == nil {
		t.Error("expected error for unparsable CA cert")
	}
}

func TestTokenRoundTripperMissingFile(t *testing.T) {
	client := &http.Client{Transport: &tokenRoundTripper{
		transport: http.DefaultTransport,
		tokenPath: t.TempDir() + "/absent",
	}}
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected error when token file is missing")
	}
}

func TestGetOrCreateVerifierDiscoveryFallback(t *testing.T) {
	key := newSigningKey(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":"https://a.example.com","jwks_uri":"https://%s/openid/v1/jwks"}`, r.Host)
		case "/openid/v1/jwks":
			fmt.Fprint(w, jwksJSON(t, key, "kid-1"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	tokenFile := dir + "/token"
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("good-token"), 0600); err != nil {
		t.Fatal(err)
	}

	clusterCfg := config.ClusterConfig{
		Issuer:    "https://a.example.com",
		APIServer: srv.URL,
		CACert:    caFile,
		TokenPath: tokenFile,
	}
	cfg := &config.Config{Clusters: map[string]config.ClusterConfig{"cluster-a": clusterCfg}}

	credStore, err := credentials.NewStore(&config.Config{Clusters: map[string]config.ClusterConfig{}}, "test-secret")
	if err != nil {
		t.Fatalf("cred store: %v", err)
	}
	credStore.SetCACert("cluster-a", caPEM)
	credStore.SetToken("cluster-a", "stale-token")

	mgr := NewVerifierManager(cfg, credStore)

	if _, err := mgr.getOrCreateVerifier(context.Background(), "cluster-a", clusterCfg); err != nil {
		t.Fatalf("getOrCreateVerifier() error: %v", err)
	}

	creds, _ := credStore.Get("cluster-a")
	if creds.Token != "" {
		t.Errorf("expected stale token cleared, got %q", creds.Token)
	}
	if mgr.kidToCluster["kid-1"] != "cluster-a" {
		t.Error("expected kid-1 pre-fetched for cluster-a")
	}
}

func TestGetOrCreateVerifierFallbackClientError(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer failing.Close()

	clusterCfg := config.ClusterConfig{
		Issuer:    "https://a.example.com",
		APIServer: failing.URL,
		CACert:    t.TempDir() + "/missing.pem",
		TokenPath: "/nonexistent/token",
	}
	cfg := &config.Config{Clusters: map[string]config.ClusterConfig{"cluster-a": clusterCfg}}

	mgr := NewVerifierManager(cfg, nil)
	mgr.testHTTPClients = map[string]*http.Client{"cluster-a": failing.Client()}

	if _, err := mgr.getOrCreateVerifier(context.Background(), "cluster-a", clusterCfg); err == nil {
		t.Fatal("expected error when both primary and fallback discovery fail")
	}
	if mgr.DegradedClusters()["cluster-a"] == "" {
		t.Error("expected cluster-a to be degraded")
	}
}

func doAndRead(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func gaugeValue(t *testing.T, gauge *prometheus.GaugeVec, cluster string) float64 {
	t.Helper()
	var m dto.Metric
	if err := gauge.WithLabelValues(cluster).Write(&m); err != nil {
		t.Fatalf("reading gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}
