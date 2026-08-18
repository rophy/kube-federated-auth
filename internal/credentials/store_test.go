package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/rophy/kube-federated-auth/internal/config"
)

func newTestStore() *Store {
	return &Store{
		credentials: make(map[string]*Credentials),
		config:      &config.Config{Clusters: make(map[string]config.ClusterConfig)},
	}
}

func writeTestFiles(t *testing.T, dir, token, ca string) (tokenPath, caPath string) {
	t.Helper()
	tokenPath = filepath.Join(dir, "token")
	caPath = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte(token), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte(ca), 0644); err != nil {
		t.Fatal(err)
	}
	return
}

func makePodBoundJWT(sub string, exp time.Time, podName string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims := map[string]interface{}{
		"sub": sub,
		"exp": exp.Unix(),
		"kubernetes.io": map[string]interface{}{
			"pod": map[string]interface{}{
				"name": podName,
				"uid":  "test-uid",
			},
		},
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return header + "." + payload + ".sig"
}

func TestIsTokenPodBound(t *testing.T) {
	t.Run("pod-bound token", func(t *testing.T) {
		token := makePodBoundJWT("system:serviceaccount:ns:sa", time.Now().Add(time.Hour), "my-pod")
		if !isTokenPodBound(token) {
			t.Error("expected pod-bound token to be detected")
		}
	})
	t.Run("regular token", func(t *testing.T) {
		token := makeJWT("system:serviceaccount:ns:sa", time.Now().Add(time.Hour))
		if isTokenPodBound(token) {
			t.Error("expected regular token to not be detected as pod-bound")
		}
	})
	t.Run("invalid JWT", func(t *testing.T) {
		if isTokenPodBound("not-a-jwt") {
			t.Error("expected invalid JWT to not be detected as pod-bound")
		}
	})
}

func TestLoadFromSecret_SkipsPodBoundTokens(t *testing.T) {
	podBoundToken := makePodBoundJWT("system:serviceaccount:ns:sa", time.Now().Add(time.Hour), "my-pod")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "test-ns"},
		Data: map[string][]byte{
			"cluster-a-token": []byte(podBoundToken),
		},
	}
	store := newTestStore()
	store.client = kubefake.NewSimpleClientset(secret)
	store.namespace = "test-ns"
	store.secretName = "creds"

	err := store.loadFromSecret(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, ok := store.Get("cluster-a")
	if ok {
		t.Error("expected pod-bound token to be skipped")
	}
}

func TestParseServiceAccountFromToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantNS  string
		wantSA  string
		wantErr bool
	}{
		{
			name:   "valid token",
			token:  makeJWT("system:serviceaccount:my-ns:my-sa", time.Now().Add(time.Hour)),
			wantNS: "my-ns",
			wantSA: "my-sa",
		},
		{
			name:    "invalid JWT format",
			token:   "not-a-jwt",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			token:   "header.!!!invalid!!!.sig",
			wantErr: true,
		},
		{
			name:    "wrong subject format",
			token:   makeJWT("just-a-user", time.Now().Add(time.Hour)),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, sa, err := parseServiceAccountFromToken(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ns != tt.wantNS {
				t.Errorf("namespace = %q, want %q", ns, tt.wantNS)
			}
			if sa != tt.wantSA {
				t.Errorf("serviceAccount = %q, want %q", sa, tt.wantSA)
			}
		})
	}
}

func TestGetTokenExpiration(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		exp := time.Now().Add(24 * time.Hour).Truncate(time.Second)
		token := makeJWT("sub", exp)
		got, err := getTokenExpiration(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.Equal(exp) {
			t.Errorf("expiration = %v, want %v", got, exp)
		}
	})
	t.Run("invalid JWT", func(t *testing.T) {
		_, err := getTokenExpiration("not-a-jwt")
		if err == nil {
			t.Error("expected error for invalid JWT")
		}
	})
	t.Run("no exp claim", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"foo"}`))
		token := header + "." + payload + ".sig"
		_, err := getTokenExpiration(token)
		if err == nil {
			t.Error("expected error for missing exp")
		}
	})
}

func TestLoadFromSecret(t *testing.T) {
	validToken := makeJWT("system:serviceaccount:ns:sa", time.Now().Add(24*time.Hour))

	t.Run("nil client is no-op", func(t *testing.T) {
		store := newTestStore()
		// client is nil by default
		err := store.loadFromSecret(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("secret not found is no error", func(t *testing.T) {
		store := newTestStore()
		store.client = kubefake.NewSimpleClientset()
		store.namespace = "test-ns"
		store.secretName = "nonexistent"

		err := store.loadFromSecret(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("secret with valid tokens", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "test-ns"},
			Data: map[string][]byte{
				"cluster-b-token": []byte(validToken),
			},
		}
		store := newTestStore()
		store.client = kubefake.NewSimpleClientset(secret)
		store.namespace = "test-ns"
		store.secretName = "creds"

		err := store.loadFromSecret(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		creds, ok := store.Get("cluster-b")
		if !ok {
			t.Fatal("expected credentials for cluster-b")
		}
		if creds.Token != validToken {
			t.Error("token mismatch")
		}
		if creds.source != tokenPersisted {
			t.Errorf("source = %d, want tokenPersisted", creds.source)
		}
	})
	t.Run("empty token skipped", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "test-ns"},
			Data: map[string][]byte{
				"cluster-b-token": []byte(""),
			},
		}
		store := newTestStore()
		store.client = kubefake.NewSimpleClientset(secret)
		store.namespace = "test-ns"
		store.secretName = "creds"

		store.loadFromSecret(context.Background())
		_, ok := store.Get("cluster-b")
		if ok {
			t.Error("expected empty token to be skipped")
		}
	})
	t.Run("key without -token suffix skipped", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "test-ns"},
			Data: map[string][]byte{
				"cluster-b-ca": []byte("some-ca-data"),
			},
		}
		store := newTestStore()
		store.client = kubefake.NewSimpleClientset(secret)
		store.namespace = "test-ns"
		store.secretName = "creds"

		store.loadFromSecret(context.Background())
		_, ok := store.Get("cluster-b-ca")
		if ok {
			t.Error("expected key without -token suffix to be skipped")
		}
	})
}

func TestSaveToSecret(t *testing.T) {
	t.Run("nil client is no-op", func(t *testing.T) {
		store := newTestStore()
		err := store.saveToSecret(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("no persisted tokens is no-op", func(t *testing.T) {
		store := newTestStore()
		store.client = kubefake.NewSimpleClientset()
		store.namespace = "test-ns"
		store.secretName = "creds"
		// Only mounted token
		store.credentials["cluster-a"] = &Credentials{Token: "tok", source: tokenMounted}

		err := store.saveToSecret(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("saves only persisted tokens", func(t *testing.T) {
		fakeClient := kubefake.NewSimpleClientset()
		store := newTestStore()
		store.client = fakeClient
		store.namespace = "test-ns"
		store.secretName = "creds"
		store.credentials["cluster-a"] = &Credentials{Token: "mounted-tok", source: tokenMounted}
		store.credentials["cluster-b"] = &Credentials{Token: "persisted-tok", source: tokenPersisted}

		err := store.saveToSecret(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		secret, err := fakeClient.CoreV1().Secrets("test-ns").Get(context.Background(), "creds", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}
		if string(secret.Data["cluster-b-token"]) != "persisted-tok" {
			t.Errorf("cluster-b-token = %q, want %q", string(secret.Data["cluster-b-token"]), "persisted-tok")
		}
		if _, ok := secret.Data["cluster-a-token"]; ok {
			t.Error("mounted token should not be in secret")
		}
	})
	t.Run("creates secret when update returns not found", func(t *testing.T) {
		fakeClient := kubefake.NewSimpleClientset()
		store := newTestStore()
		store.client = fakeClient
		store.namespace = "test-ns"
		store.secretName = "creds"
		store.credentials["cluster-b"] = &Credentials{Token: "tok", source: tokenPersisted}

		err := store.saveToSecret(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify secret was created
		secret, err := fakeClient.CoreV1().Secrets("test-ns").Get(context.Background(), "creds", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("secret should have been created: %v", err)
		}
		if string(secret.Data["cluster-b-token"]) != "tok" {
			t.Errorf("token = %q, want %q", string(secret.Data["cluster-b-token"]), "tok")
		}
	})
}

func TestRenewToken_Dispatch(t *testing.T) {
	t.Run("mounted source calls renewMountedToken path", func(t *testing.T) {
		dir := t.TempDir()
		tokenPath := filepath.Join(dir, "token")
		os.WriteFile(tokenPath, []byte("new-token"), 0644)

		cfg := &config.Config{
			Clusters: map[string]config.ClusterConfig{
				"cluster-a": {Issuer: "https://example.com", TokenPath: tokenPath},
			},
		}
		store := newTestStoreWithConfig(cfg)
		store.credentials["cluster-a"] = &Credentials{Token: "old-token", source: tokenMounted}

		err := store.renewToken(context.Background(), "cluster-a", cfg.Clusters["cluster-a"])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		creds, _ := store.Get("cluster-a")
		if creds.Token != "new-token" {
			t.Errorf("token = %q, want %q", creds.Token, "new-token")
		}
	})
	t.Run("unknown source returns error", func(t *testing.T) {
		cfg := &config.Config{
			Clusters: map[string]config.ClusterConfig{
				"cluster-a": {Issuer: "https://example.com"},
			},
		}
		store := newTestStoreWithConfig(cfg)
		store.credentials["cluster-a"] = &Credentials{Token: "tok", source: tokenSource(99)}

		err := store.renewToken(context.Background(), "cluster-a", cfg.Clusters["cluster-a"])
		if err == nil {
			t.Error("expected error for unknown source")
		}
	})
}

func TestSetCACert_LoadsWhenEmpty(t *testing.T) {
	store := newTestStore()
	store.SetCACert("cluster-b", []byte("test-ca"))

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be created")
	}
	if string(creds.CACert) != "test-ca" {
		t.Errorf("expected CA cert 'test-ca', got '%s'", string(creds.CACert))
	}
	if creds.Token != "" {
		t.Errorf("expected empty token, got '%s'", creds.Token)
	}
}

func TestSetCACert_SetsCAOnExisting(t *testing.T) {
	store := newTestStore()
	store.credentials["cluster-b"] = &Credentials{Token: "existing-token"}

	store.SetCACert("cluster-b", []byte("test-ca"))

	creds, _ := store.Get("cluster-b")
	if creds.Token != "existing-token" {
		t.Errorf("expected token preserved, got '%s'", creds.Token)
	}
	if string(creds.CACert) != "test-ca" {
		t.Errorf("expected CA cert 'test-ca', got '%s'", string(creds.CACert))
	}
}

func TestSetToken_LoadsWhenEmpty(t *testing.T) {
	store := newTestStore()
	store.SetToken("cluster-b", "test-token")

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be created")
	}
	if creds.Token != "test-token" {
		t.Errorf("expected token 'test-token', got '%s'", creds.Token)
	}
}

func TestSetToken_OverwritesExisting(t *testing.T) {
	store := newTestStore()
	store.credentials["cluster-b"] = &Credentials{
		Token:  "old-token",
		CACert: []byte("existing-ca"),
	}

	store.SetToken("cluster-b", "new-token")

	creds, _ := store.Get("cluster-b")
	if creds.Token != "new-token" {
		t.Errorf("expected token 'new-token', got '%s'", creds.Token)
	}
	if string(creds.CACert) != "existing-ca" {
		t.Errorf("expected CA cert preserved, got '%s'", string(creds.CACert))
	}
}

func TestNewStore_LoadsFromFiles(t *testing.T) {
	dir := t.TempDir()
	tokenPath, caPath := writeTestFiles(t, dir, "bootstrap-token", "test-ca")

	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-b": {
				Issuer:    "https://example.com",
				TokenPath: tokenPath,
				CACert:    caPath,
			},
		},
	}

	store, err := NewStore(cfg, "test-secret")
	if err != nil {
		t.Fatal(err)
	}

	creds, ok := store.Get("cluster-b")
	if !ok {
		t.Fatal("expected credentials to be created")
	}
	if creds.Token != "bootstrap-token" {
		t.Errorf("expected token 'bootstrap-token', got '%s'", creds.Token)
	}
	if string(creds.CACert) != "test-ca" {
		t.Errorf("expected CA cert 'test-ca', got '%s'", string(creds.CACert))
	}
	if creds.source != tokenMounted {
		t.Errorf("expected source tokenMounted, got %d", creds.source)
	}
}

func TestNewStore_SkipsMissingFiles(t *testing.T) {
	cfg := &config.Config{
		Clusters: map[string]config.ClusterConfig{
			"cluster-b": {
				Issuer:    "https://example.com",
				TokenPath: "/nonexistent/token",
				CACert:    "/nonexistent/ca.crt",
			},
		},
	}

	store, err := NewStore(cfg, "test-secret")
	if err != nil {
		t.Fatal(err)
	}

	_, ok := store.Get("cluster-b")
	if ok {
		t.Error("expected no credentials for missing files")
	}
}

func TestRenewMountedToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	os.WriteFile(tokenPath, []byte("original-token"), 0644)

	store := newTestStore()
	store.credentials["cluster-a"] = &Credentials{
		Token:  "original-token",
		source: tokenMounted,
	}

	cfg := config.ClusterConfig{TokenPath: tokenPath}

	// Write new token to file (simulating kubelet rotation)
	os.WriteFile(tokenPath, []byte("rotated-token"), 0644)

	if err := store.renewMountedToken("cluster-a", cfg); err != nil {
		t.Fatal(err)
	}

	creds, _ := store.Get("cluster-a")
	if creds.Token != "rotated-token" {
		t.Errorf("expected 'rotated-token', got '%s'", creds.Token)
	}
	if creds.source != tokenMounted {
		t.Errorf("expected source tokenMounted after renewal")
	}
}

type countingVerifier struct {
	mu    sync.Mutex
	calls int
}

func (c *countingVerifier) InvalidateVerifier(string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
}

func (c *countingVerifier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestClearToken(t *testing.T) {
	t.Run("clears existing token", func(t *testing.T) {
		store := newTestStore()
		store.credentials["cluster-b"] = &Credentials{Token: "tok", CACert: []byte("ca"), source: tokenPersisted}

		store.ClearToken("cluster-b")

		creds, _ := store.Get("cluster-b")
		if creds.Token != "" {
			t.Errorf("token = %q, want empty", creds.Token)
		}
		if creds.source != tokenMounted {
			t.Errorf("source = %d, want tokenMounted", creds.source)
		}
		if string(creds.CACert) != "ca" {
			t.Error("CA cert should be preserved")
		}
	})
	t.Run("unknown cluster is no-op", func(t *testing.T) {
		store := newTestStore()
		store.ClearToken("missing")
		if _, ok := store.Get("missing"); ok {
			t.Error("expected no credentials to be created")
		}
	})
}

func TestSetMetrics(t *testing.T) {
	store := newTestStore()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_renewal_total"}, []string{"cluster", "result"})
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_expiry_seconds"}, []string{"cluster"})

	store.SetMetrics(counter, gauge)

	if store.renewalTotal != counter || store.expirySeconds != gauge {
		t.Error("expected metrics to be set")
	}
}

func TestTryRenew_RecordsMetricsAndInvalidatesVerifier(t *testing.T) {
	renewedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(168*time.Hour))
	storedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(time.Minute))

	cfg := defaultConfig()
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: storedToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFakeClient(t, renewedToken))

	store.SetMetrics(
		prometheus.NewCounterVec(prometheus.CounterOpts{Name: "renewal_total"}, []string{"cluster", "result"}),
		prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "expiry_seconds"}, []string{"cluster"}),
	)

	verifier := &countingVerifier{}
	store.verifier = verifier

	store.tryRenew(context.Background())

	got, _ := store.Get("cluster-b")
	if got.Token != renewedToken {
		t.Error("expected token to be renewed")
	}
	if verifier.count() != 1 {
		t.Errorf("verifier calls = %d, want 1", verifier.count())
	}
}

func TestTryRenew_RecordsFailureMetric(t *testing.T) {
	storedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(time.Minute))

	cfg := defaultConfig()
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: storedToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFailingClient(t))

	store.SetMetrics(prometheus.NewCounterVec(prometheus.CounterOpts{Name: "renewal_total"}, []string{"cluster", "result"}), nil)

	store.tryRenew(context.Background())

	got, _ := store.Get("cluster-b")
	if got.Token != storedToken {
		t.Error("expected token to be unchanged after failed renewal")
	}
}

func TestTryRenew_SkipsClusterWithoutToken(t *testing.T) {
	cfg := defaultConfig()
	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: "", source: tokenPersisted}

	verifier := &countingVerifier{}
	store.verifier = verifier

	store.tryRenew(context.Background())

	if verifier.count() != 0 {
		t.Errorf("verifier calls = %d, want 0", verifier.count())
	}
}

func TestTryRenew_PersistsToSecretAfterRenewal(t *testing.T) {
	renewedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(168*time.Hour))
	storedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(time.Minute))

	cfg := defaultConfig()
	cfg.Renewal = &config.RenewalSettings{RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: storedToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFakeClient(t, renewedToken))
	store.client = kubefake.NewSimpleClientset()
	store.namespace = "test-ns"
	store.secretName = "creds"

	store.tryRenew(context.Background())

	secret, err := store.client.CoreV1().Secrets("test-ns").Get(context.Background(), "creds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret to be persisted: %v", err)
	}
	if string(secret.Data["cluster-b-token"]) != renewedToken {
		t.Error("expected renewed token in secret")
	}
}

func TestStart_RenewLoopRunsAndStopsOnCancel(t *testing.T) {
	renewedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(168*time.Hour))
	storedToken := makeJWT("system:serviceaccount:kube-federated-auth:reader", time.Now().Add(time.Minute))

	cfg := defaultConfig()
	cfg.Renewal = &config.RenewalSettings{Interval: 5 * time.Millisecond, RenewBefore: 8760 * time.Hour}

	store := newTestStoreWithConfig(cfg)
	store.credentials["cluster-b"] = &Credentials{Token: storedToken, CACert: []byte("ca"), source: tokenPersisted}
	store.newClient = fakeClientFactory(setupFakeClient(t, renewedToken))

	verifier := &countingVerifier{}
	ctx, cancel := context.WithCancel(context.Background())
	store.Start(ctx, verifier)

	deadline := time.Now().Add(2 * time.Second)
	for verifier.count() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("renewal loop did not tick, calls = %d", verifier.count())
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
	stopped := verifier.count()
	time.Sleep(50 * time.Millisecond)
	if verifier.count() != stopped {
		t.Errorf("loop kept running after cancel: %d -> %d", stopped, verifier.count())
	}
}

func TestCreateClient(t *testing.T) {
	store := newTestStore()
	cfg := config.ClusterConfig{APIServer: "https://10.0.0.1:6443"}

	t.Run("with credentials", func(t *testing.T) {
		ca := generateCACert(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		client, err := store.createClient(cfg, &Credentials{Token: "tok", CACert: ca})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Error("expected client")
		}
	})
	t.Run("nil credentials", func(t *testing.T) {
		client, err := store.createClient(cfg, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Error("expected client")
		}
	})
	t.Run("invalid CA data", func(t *testing.T) {
		_, err := store.createClient(cfg, &Credentials{Token: "tok", CACert: []byte("not-a-cert")})
		if err == nil {
			t.Error("expected error for invalid CA data")
		}
	})
}

func TestDetectNamespace(t *testing.T) {
	if ns := detectNamespace(); ns != "kube-federated-auth" {
		t.Errorf("namespace = %q, want %q", ns, "kube-federated-auth")
	}
}
