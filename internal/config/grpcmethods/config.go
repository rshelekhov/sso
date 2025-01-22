package grpc

import (
	"fmt"
	"strings"
)

type MethodsConfig struct {
	publicMethods map[string]bool
}

func NewMethodsConfig(cfg *Config) (*MethodsConfig, error) {
	grpcMethodsConfig := &MethodsConfig{
		publicMethods: make(map[string]bool),
	}

	for _, method := range cfg.GRPC.PublicMethods {
		grpcMethodsConfig.AddPublicMethod(method)
	}

	if err := grpcMethodsConfig.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate grpc methods config: %w", err)
	}

	return grpcMethodsConfig, nil
}

func (c *MethodsConfig) AddPublicMethod(method string) {
	c.publicMethods[method] = true
}

func (c *MethodsConfig) IsPublic(method string) bool {
	return c.publicMethods[method]
}

func (c *MethodsConfig) Validate() error {
	for method := range c.publicMethods {
		if !strings.HasPrefix(method, "/") || strings.Count(method, "/") != 2 {
			return fmt.Errorf("invalid public method format: %s", method)
		}
	}
	return nil
}
