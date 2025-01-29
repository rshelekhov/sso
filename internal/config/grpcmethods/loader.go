package grpcmethods

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func Load(configPath string) (*Config, error) {
	if configPath == "" {
		return nil, fmt.Errorf("config path for loading grpc methods is empty")
	}

	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read config file for loading grpc methods: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file for loading grpc methods: %w", err)
	}

	return &cfg, nil
}
