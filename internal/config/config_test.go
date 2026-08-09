package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
  cluster-b:
    issuer: "https://oidc.other.com"
    ca_cert: "/path/to/ca.crt"
    token_path: "/path/to/token"
`
	cfg := loadFromString(t, content)

	if len(cfg.Clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(cfg.Clusters))
	}

	a, ok := cfg.Clusters["cluster-a"]
	if !ok {
		t.Fatal("cluster-a not found")
	}
	if a.Issuer != "https://oidc.example.com" {
		t.Errorf("cluster-a issuer = %q, want %q", a.Issuer, "https://oidc.example.com")
	}
	if a.CACert != "" {
		t.Errorf("cluster-a ca_cert = %q, want empty", a.CACert)
	}

	b, ok := cfg.Clusters["cluster-b"]
	if !ok {
		t.Fatal("cluster-b not found")
	}
	if b.Issuer != "https://oidc.other.com" {
		t.Errorf("cluster-b issuer = %q, want %q", b.Issuer, "https://oidc.other.com")
	}
	if b.CACert != "/path/to/ca.crt" {
		t.Errorf("cluster-b ca_cert = %q, want %q", b.CACert, "/path/to/ca.crt")
	}
	if b.TokenPath != "/path/to/token" {
		t.Errorf("cluster-b token_path = %q, want %q", b.TokenPath, "/path/to/token")
	}
}

func TestLoad_EmptyClusters(t *testing.T) {
	content := `clusters: {}`

	_, err := loadFromStringErr(content)
	if err == nil {
		t.Error("expected error for empty clusters, got nil")
	}
}

func TestLoad_MissingIssuer(t *testing.T) {
	content := `
clusters:
  cluster-a:
    ca_cert: "/path/to/ca.crt"
`
	_, err := loadFromStringErr(content)
	if err == nil {
		t.Error("expected error for missing issuer, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	content := `not: valid: yaml: [[[`

	_, err := loadFromStringErr(content)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestClusterNames(t *testing.T) {
	content := `
clusters:
  alpha:
    issuer: "https://alpha.example.com"
  beta:
    issuer: "https://beta.example.com"
  gamma:
    issuer: "https://gamma.example.com"
`
	cfg := loadFromString(t, content)

	names := cfg.ClusterNames()
	if len(names) != 3 {
		t.Errorf("expected 3 names, got %d", len(names))
	}

	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}

	for _, expected := range []string{"alpha", "beta", "gamma"} {
		if !nameSet[expected] {
			t.Errorf("expected %q in cluster names", expected)
		}
	}
}

func TestLoad_WithGlobalRenewalSettings(t *testing.T) {
	content := `
renewal:
  interval: "2h"
  token_duration: "48h"
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
  cluster-b:
    issuer: "https://kubernetes.default.svc.cluster.local"
    api_server: "https://cluster-b.example.com:6443"
    ca_cert: "/path/to/ca.crt"
    token_path: "/path/to/token"
`
	cfg := loadFromString(t, content)

	if len(cfg.Clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(cfg.Clusters))
	}

	// Test global renewal settings
	if cfg.GetRenewalInterval().Hours() != 2 {
		t.Errorf("interval = %v, want 2h", cfg.GetRenewalInterval())
	}
	if cfg.GetRenewalTokenDuration().Hours() != 48 {
		t.Errorf("token_duration = %v, want 48h", cfg.GetRenewalTokenDuration())
	}

	// Test IsRemote
	a := cfg.Clusters["cluster-a"]
	if a.IsRemote() {
		t.Error("cluster-a should not be remote")
	}

	b := cfg.Clusters["cluster-b"]
	if !b.IsRemote() {
		t.Error("cluster-b should be remote")
	}
}

func TestGetRemoteClusters(t *testing.T) {
	content := `
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
  cluster-b:
    issuer: "https://oidc.other.com"
    api_server: "https://cluster-b.example.com:6443"
  cluster-c:
    issuer: "https://oidc.third.com"
`
	cfg := loadFromString(t, content)

	remoteClusters := cfg.GetRemoteClusters()
	if len(remoteClusters) != 1 {
		t.Errorf("expected 1 remote cluster, got %d", len(remoteClusters))
	}
	if len(remoteClusters) > 0 && remoteClusters[0] != "cluster-b" {
		t.Errorf("expected cluster-b, got %s", remoteClusters[0])
	}
}

func TestRenewalDefaults(t *testing.T) {
	content := `
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
`
	cfg := loadFromString(t, content)

	// Should use defaults when no renewal config
	if cfg.GetRenewalInterval() != DefaultRenewalInterval {
		t.Errorf("interval = %v, want %v", cfg.GetRenewalInterval(), DefaultRenewalInterval)
	}
	if cfg.GetRenewalTokenDuration() != DefaultRenewalTokenDuration {
		t.Errorf("token_duration = %v, want %v", cfg.GetRenewalTokenDuration(), DefaultRenewalTokenDuration)
	}
}

func TestIsAuthorizedClient_ExactMatch(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{"cluster-a/default/my-app"},
	}
	if !cfg.IsAuthorizedClient("cluster-a", "default", "my-app") {
		t.Error("expected exact match to be authorized")
	}
}

func TestIsAuthorizedClient_WildcardCluster(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{"*/default/my-app"},
	}
	if !cfg.IsAuthorizedClient("cluster-b", "default", "my-app") {
		t.Error("expected wildcard cluster to match")
	}
}

func TestIsAuthorizedClient_WildcardNamespace(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{"cluster-a/*/my-app"},
	}
	if !cfg.IsAuthorizedClient("cluster-a", "some-ns", "my-app") {
		t.Error("expected wildcard namespace to match")
	}
}

func TestIsAuthorizedClient_WildcardServiceAccount(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{"cluster-a/default/*"},
	}
	if !cfg.IsAuthorizedClient("cluster-a", "default", "any-sa") {
		t.Error("expected wildcard service account to match")
	}
}

func TestIsAuthorizedClient_AllWildcards(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{"*/*/*"},
	}
	if !cfg.IsAuthorizedClient("any-cluster", "any-ns", "any-sa") {
		t.Error("expected all wildcards to match anything")
	}
}

func TestIsAuthorizedClient_NoMatch(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{"cluster-a/default/my-app"},
	}
	if cfg.IsAuthorizedClient("cluster-b", "default", "my-app") {
		t.Error("expected no match for different cluster")
	}
}

func TestIsAuthorizedClient_EmptyList(t *testing.T) {
	cfg := &Config{}
	if cfg.IsAuthorizedClient("cluster-a", "default", "my-app") {
		t.Error("expected empty list to deny all")
	}
}

func TestIsAuthorizedClient_MultipleEntries(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{
			"cluster-a/default/app-1",
			"cluster-b/*/proxy",
		},
	}
	if !cfg.IsAuthorizedClient("cluster-b", "kube-system", "proxy") {
		t.Error("expected second entry to match")
	}
	if cfg.IsAuthorizedClient("cluster-c", "default", "app-1") {
		t.Error("expected no match for cluster-c")
	}
}

func TestIsAuthorizedClient_MalformedEntry(t *testing.T) {
	cfg := &Config{
		AuthorizedClients: []string{"only-two/segments"},
	}
	if cfg.IsAuthorizedClient("only-two", "segments", "anything") {
		t.Error("expected malformed entry to not match")
	}
}

func TestDiscoveryURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  ClusterConfig
		want string
	}{
		{
			name: "api_server set",
			cfg:  ClusterConfig{Issuer: "https://issuer.example.com", APIServer: "https://api.example.com"},
			want: "https://api.example.com",
		},
		{
			name: "api_server empty falls back to issuer",
			cfg:  ClusterConfig{Issuer: "https://issuer.example.com"},
			want: "https://issuer.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.DiscoveryURL(); got != tt.want {
				t.Errorf("DiscoveryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"DEBUG", slog.LevelDebug},
		{"debug", slog.LevelDebug},
		{"WARN", slog.LevelWarn},
		{"warn", slog.LevelWarn},
		{"ERROR", slog.LevelError},
		{"error", slog.LevelError},
		{"INFO", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"bogus", slog.LevelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cfg := &Config{LogLevel: tt.input}
			if got := cfg.GetLogLevel(); got != tt.want {
				t.Errorf("GetLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetRenewalRenewBefore(t *testing.T) {
	t.Run("custom value", func(t *testing.T) {
		cfg := &Config{Renewal: &RenewalSettings{RenewBefore: 24 * time.Hour}}
		if got := cfg.GetRenewalRenewBefore(); got != 24*time.Hour {
			t.Errorf("GetRenewalRenewBefore() = %v, want 24h", got)
		}
	})
	t.Run("nil renewal returns default", func(t *testing.T) {
		cfg := &Config{}
		if got := cfg.GetRenewalRenewBefore(); got != DefaultRenewalRenewBefore {
			t.Errorf("GetRenewalRenewBefore() = %v, want %v", got, DefaultRenewalRenewBefore)
		}
	})
	t.Run("zero value returns default", func(t *testing.T) {
		cfg := &Config{Renewal: &RenewalSettings{}}
		if got := cfg.GetRenewalRenewBefore(); got != DefaultRenewalRenewBefore {
			t.Errorf("GetRenewalRenewBefore() = %v, want %v", got, DefaultRenewalRenewBefore)
		}
	})
}

func TestLoad_GlobalCacheSettings(t *testing.T) {
	content := `
cache:
  ttl: 60
  max_entries: 1000
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
`
	cfg := loadFromString(t, content)

	if cfg.Cache == nil {
		t.Fatal("expected global cache settings")
	}
	if cfg.Cache.TTL != 60 {
		t.Errorf("TTL = %d, want 60", cfg.Cache.TTL)
	}
	if cfg.Cache.MaxEntries != 1000 {
		t.Errorf("MaxEntries = %d, want 1000", cfg.Cache.MaxEntries)
	}
}

func TestLoad_PerClusterCacheSettings(t *testing.T) {
	content := `
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
    cache:
      ttl: 30
      max_entries: 500
  cluster-b:
    issuer: "https://oidc.other.com"
`
	cfg := loadFromString(t, content)

	a := cfg.Clusters["cluster-a"]
	if a.Cache == nil {
		t.Fatal("expected per-cluster cache settings for cluster-a")
	}
	if a.Cache.TTL != 30 {
		t.Errorf("cluster-a TTL = %d, want 30", a.Cache.TTL)
	}
	if a.Cache.MaxEntries != 500 {
		t.Errorf("cluster-a MaxEntries = %d, want 500", a.Cache.MaxEntries)
	}

	b := cfg.Clusters["cluster-b"]
	if b.Cache != nil {
		t.Errorf("expected nil cache for cluster-b, got %+v", b.Cache)
	}
}

func TestGetCacheSettings_Resolution(t *testing.T) {
	content := `
cache:
  ttl: 60
  max_entries: 1000
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
    cache:
      ttl: 30
      max_entries: 500
  cluster-b:
    issuer: "https://oidc.other.com"
  cluster-c:
    issuer: "https://oidc.third.com"
`
	cfg := loadFromString(t, content)

	// Per-cluster overrides global
	cs := cfg.GetCacheSettings("cluster-a")
	if cs == nil {
		t.Fatal("expected cache settings for cluster-a")
	}
	if cs.TTL != 30 {
		t.Errorf("cluster-a TTL = %d, want 30", cs.TTL)
	}

	// Falls back to global
	cs = cfg.GetCacheSettings("cluster-b")
	if cs == nil {
		t.Fatal("expected global cache settings for cluster-b")
	}
	if cs.TTL != 60 {
		t.Errorf("cluster-b TTL = %d, want 60 (global)", cs.TTL)
	}

	// Unknown cluster falls back to global
	cs = cfg.GetCacheSettings("unknown")
	if cs == nil {
		t.Fatal("expected global cache settings for unknown cluster")
	}
	if cs.TTL != 60 {
		t.Errorf("unknown cluster TTL = %d, want 60 (global)", cs.TTL)
	}
}

func TestGetCacheSettings_DefaultsWhenNoCacheConfigured(t *testing.T) {
	content := `
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
`
	cfg := loadFromString(t, content)

	cs := cfg.GetCacheSettings("cluster-a")
	if cs == nil {
		t.Fatal("expected default cache settings, got nil")
	}
	if cs.TTL != DefaultCacheTTL {
		t.Errorf("TTL = %d, want %d", cs.TTL, DefaultCacheTTL)
	}
	if cs.MaxEntries != DefaultMaxEntries {
		t.Errorf("MaxEntries = %d, want %d", cs.MaxEntries, DefaultMaxEntries)
	}
}

func TestLoad_QPSAndBurst(t *testing.T) {
	content := `
clusters:
  cluster-a:
    issuer: "https://oidc.example.com"
    qps: 100
    burst: 200
  cluster-b:
    issuer: "https://oidc.other.com"
`
	cfg := loadFromString(t, content)

	a := cfg.Clusters["cluster-a"]
	if a.QPS != 100 {
		t.Errorf("cluster-a QPS = %v, want 100", a.QPS)
	}
	if a.Burst != 200 {
		t.Errorf("cluster-a Burst = %d, want 200", a.Burst)
	}

	b := cfg.Clusters["cluster-b"]
	if b.QPS != 0 {
		t.Errorf("cluster-b QPS = %v, want 0", b.QPS)
	}
	if b.Burst != 0 {
		t.Errorf("cluster-b Burst = %d, want 0", b.Burst)
	}
}

// Helper functions

func loadFromString(t *testing.T, content string) *Config {
	t.Helper()
	cfg, err := loadFromStringErr(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return cfg
}

func loadFromStringErr(content string) (*Config, error) {
	dir, err := os.MkdirTemp("", "config-test")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return nil, err
	}

	return Load(path)
}
