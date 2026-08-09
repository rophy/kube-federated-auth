package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultRenewalInterval      = 1 * time.Hour
	DefaultRenewalTokenDuration = 168 * time.Hour // 7 days
	DefaultRenewalRenewBefore   = 48 * time.Hour  // 2 days
)

// RenewalSettings contains global settings for token renewal
type RenewalSettings struct {
	Interval      time.Duration `yaml:"interval"`
	TokenDuration time.Duration `yaml:"token_duration"`
	RenewBefore   time.Duration `yaml:"renew_before"`
}

// UnmarshalYAML handles duration parsing from string
func (r *RenewalSettings) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawRenewalSettings struct {
		Interval      string `yaml:"interval"`
		TokenDuration string `yaml:"token_duration"`
		RenewBefore   string `yaml:"renew_before"`
	}
	var raw rawRenewalSettings
	if err := unmarshal(&raw); err != nil {
		return err
	}

	if raw.Interval != "" {
		d, err := time.ParseDuration(raw.Interval)
		if err != nil {
			return fmt.Errorf("parsing interval: %w", err)
		}
		r.Interval = d
	}

	if raw.TokenDuration != "" {
		d, err := time.ParseDuration(raw.TokenDuration)
		if err != nil {
			return fmt.Errorf("parsing token_duration: %w", err)
		}
		r.TokenDuration = d
	}

	if raw.RenewBefore != "" {
		d, err := time.ParseDuration(raw.RenewBefore)
		if err != nil {
			return fmt.Errorf("parsing renew_before: %w", err)
		}
		r.RenewBefore = d
	}

	return nil
}

// CacheSettings configures the TokenReview response cache.
type CacheSettings struct {
	TTL         int `yaml:"ttl"`          // seconds, 0 = disabled
	NegativeTTL int `yaml:"negative_ttl"` // seconds for unauthenticated results, 0 = disabled (default: 30)
	MaxEntries  int `yaml:"max_entries"`  // max cached entries, 0 = disabled
}

const (
	DefaultNegativeTTL   = 30   // seconds
	DefaultCacheTTL      = 60   // seconds
	DefaultMaxEntries    = 1000
)

// GetNegativeTTL returns the negative TTL, defaulting to DefaultNegativeTTL if not set.
func (cs *CacheSettings) GetNegativeTTL() int {
	if cs.NegativeTTL > 0 {
		return cs.NegativeTTL
	}
	return DefaultNegativeTTL
}

type ClusterConfig struct {
	Issuer    string         `yaml:"issuer"`
	APIServer string         `yaml:"api_server,omitempty"` // Override URL for OIDC discovery
	CACert    string         `yaml:"ca_cert,omitempty"`
	TokenPath string         `yaml:"token_path,omitempty"`
	Cache     *CacheSettings `yaml:"cache,omitempty"`
	QPS       float32        `yaml:"qps,omitempty"`
	Burst     int            `yaml:"burst,omitempty"`
}

// DiscoveryURL returns the URL to use for OIDC discovery.
// If api_server is set, use it; otherwise use issuer.
func (c *ClusterConfig) DiscoveryURL() string {
	if c.APIServer != "" {
		return c.APIServer
	}
	return c.Issuer
}

// IsRemote returns true if this cluster requires remote access (has api_server set)
func (c *ClusterConfig) IsRemote() bool {
	return c.APIServer != ""
}

// MetricsLabels controls optional high-cardinality labels on tokenreview metrics.
type MetricsLabels struct {
	Client bool `yaml:"client"` // Add client (payload token SA) label to kfa_tokenreview_requests_total
}

// MetricsSettings configures Prometheus metrics behavior.
type MetricsSettings struct {
	Labels MetricsLabels `yaml:"labels"`
}

type Config struct {
	LogLevel          string                   `yaml:"log_level,omitempty"` // DEBUG, INFO, WARN, ERROR (default: INFO)
	AuthorizedClients []string                 `yaml:"authorized_clients,omitempty"`
	Renewal           *RenewalSettings         `yaml:"renewal,omitempty"`
	Cache             *CacheSettings           `yaml:"cache,omitempty"`
	Metrics           *MetricsSettings         `yaml:"metrics,omitempty"`
	Clusters          map[string]ClusterConfig `yaml:"clusters"`
}

// ClientMetricsEnabled returns whether the client label is enabled on tokenreview metrics.
func (c *Config) ClientMetricsEnabled() bool {
	return c.Metrics != nil && c.Metrics.Labels.Client
}

// GetLogLevel returns the configured slog.Level, defaulting to INFO.
func (c *Config) GetLogLevel() slog.Level {
	switch strings.ToUpper(c.LogLevel) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// IsAuthorizedClient checks if a caller identity matches the authorized_clients whitelist.
// Each entry is in format "cluster/namespace/serviceaccount" with optional "*" wildcards.
// Returns false if the whitelist is empty (deny all by default).
func (c *Config) IsAuthorizedClient(cluster, namespace, serviceAccount string) bool {
	for _, entry := range c.AuthorizedClients {
		parts := strings.SplitN(entry, "/", 3)
		if len(parts) != 3 {
			continue
		}
		if matchSegment(parts[0], cluster) && matchSegment(parts[1], namespace) && matchSegment(parts[2], serviceAccount) {
			return true
		}
	}
	return false
}

func matchSegment(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

// GetRenewalInterval returns the configured renewal interval or default
func (c *Config) GetRenewalInterval() time.Duration {
	if c.Renewal != nil && c.Renewal.Interval > 0 {
		return c.Renewal.Interval
	}
	return DefaultRenewalInterval
}

// GetRenewalTokenDuration returns the configured token duration or default
func (c *Config) GetRenewalTokenDuration() time.Duration {
	if c.Renewal != nil && c.Renewal.TokenDuration > 0 {
		return c.Renewal.TokenDuration
	}
	return DefaultRenewalTokenDuration
}

// GetRenewalRenewBefore returns the configured renew_before threshold or default
func (c *Config) GetRenewalRenewBefore() time.Duration {
	if c.Renewal != nil && c.Renewal.RenewBefore > 0 {
		return c.Renewal.RenewBefore
	}
	return DefaultRenewalRenewBefore
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if len(cfg.Clusters) == 0 {
		return nil, fmt.Errorf("no clusters configured")
	}

	for name, cluster := range cfg.Clusters {
		if cluster.Issuer == "" {
			return nil, fmt.Errorf("cluster %q: issuer is required", name)
		}
	}

	return &cfg, nil
}

// DefaultCacheSettings returns the built-in default cache settings.
var DefaultCacheSettings = &CacheSettings{
	TTL:        DefaultCacheTTL,
	MaxEntries: DefaultMaxEntries,
}

// GetCacheSettings returns the cache settings for a cluster.
// Per-cluster settings take precedence over global settings.
// Falls back to built-in defaults if no cache is configured.
func (c *Config) GetCacheSettings(clusterName string) *CacheSettings {
	if cluster, ok := c.Clusters[clusterName]; ok && cluster.Cache != nil {
		return cluster.Cache
	}
	if c.Cache != nil {
		return c.Cache
	}
	return DefaultCacheSettings
}

func (c *Config) ClusterNames() []string {
	names := make([]string, 0, len(c.Clusters))
	for name := range c.Clusters {
		names = append(names, name)
	}
	return names
}

// GetRemoteClusters returns cluster names that are remote (have api_server set)
func (c *Config) GetRemoteClusters() []string {
	var names []string
	for name, cfg := range c.Clusters {
		if cfg.IsRemote() {
			names = append(names, name)
		}
	}
	return names
}
