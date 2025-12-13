package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ClusterConfig struct {
	Issuer    string `yaml:"issuer"`
	CACert    string `yaml:"ca_cert,omitempty"`
	TokenPath string `yaml:"token_path,omitempty"`
}

type Config struct {
	Clusters map[string]ClusterConfig `yaml:"clusters"`
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
