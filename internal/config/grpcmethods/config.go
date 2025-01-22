package grpcmethods

import (
	"fmt"
	"strings"
)

type Methods struct {
	publicMethods map[string]bool
}

func New(cfg *Config) (*Methods, error) {
	methods := &Methods{
		publicMethods: make(map[string]bool),
	}

	for _, method := range cfg.Service.PublicMethods {
		methods.AddPublicMethod(method)
	}

	if err := methods.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate grpc methods config: %w", err)
	}

	return methods, nil
}

func (c *Methods) AddPublicMethod(method string) {
	c.publicMethods[method] = true
}

func (c *Methods) IsPublic(method string) bool {
	return c.publicMethods[method]
}

func (c *Methods) Validate() error {
	for method := range c.publicMethods {
		if !strings.HasPrefix(method, "/") || strings.Count(method, "/") != 2 {
			return fmt.Errorf("invalid public method format: %s", method)
		}
	}
	return nil
}
