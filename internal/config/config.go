package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

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

// AgentConfig defines which ServiceAccount is authorized to register credentials for a cluster
type AgentConfig struct {
	ServiceAccount string `yaml:"serviceAccount"`
}

type Config struct {
	Clusters map[string]ClusterConfig `yaml:"clusters"`
	Agents   map[string]AgentConfig   `yaml:"agents,omitempty"`
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

// IsAgentAuthorized checks if a ServiceAccount is authorized to register credentials for a cluster
func (c *Config) IsAgentAuthorized(cluster, serviceAccount string) bool {
	agent, ok := c.Agents[cluster]
	if !ok {
		return false
	}
	return agent.ServiceAccount == serviceAccount
}

// GetAgentClusters returns cluster names that have agent configuration
func (c *Config) GetAgentClusters() []string {
	names := make([]string, 0, len(c.Agents))
	for name := range c.Agents {
		names = append(names, name)
	}
	return names
}
