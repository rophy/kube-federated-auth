package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultRenewalInterval      = 1 * time.Hour
	DefaultRenewalTokenDuration = 24 * time.Hour
)

// RenewalSettings contains global settings for token renewal
type RenewalSettings struct {
	Interval      time.Duration `yaml:"interval"`
	TokenDuration time.Duration `yaml:"token_duration"`
}

// UnmarshalYAML handles duration parsing from string
func (r *RenewalSettings) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawRenewalSettings struct {
		Interval      string `yaml:"interval"`
		TokenDuration string `yaml:"token_duration"`
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

	return nil
}

type ClusterConfig struct {
	Issuer    string `yaml:"issuer"`
	APIServer string `yaml:"api_server,omitempty"` // Override URL for OIDC discovery
	CACert    string `yaml:"ca_cert,omitempty"`
	TokenPath string `yaml:"token_path,omitempty"`
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

type Config struct {
	Renewal  *RenewalSettings          `yaml:"renewal,omitempty"`
	Clusters map[string]ClusterConfig `yaml:"clusters"`
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
