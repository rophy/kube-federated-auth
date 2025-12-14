package config

import (
	"os"
	"path/filepath"
	"testing"
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
    api_server: "https://192.168.1.100:6443"
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
    api_server: "https://192.168.1.100:6443"
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
