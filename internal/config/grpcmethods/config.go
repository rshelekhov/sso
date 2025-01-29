package grpcmethods

import (
	"fmt"
	"strings"
)

type Methods struct {
	tokenRequiredMethods map[string]bool
	appIDRequiredMethods map[string]bool
}

func New(cfg *Config) (*Methods, error) {
	methods := &Methods{
		tokenRequiredMethods: make(map[string]bool),
		appIDRequiredMethods: make(map[string]bool),
	}

	// Validate and add public methods
	for _, method := range cfg.Service.TokenRequiredMethods {
		if err := validateMethodFormat(method); err != nil {
			return nil, fmt.Errorf("invalid public method format: %w", err)
		}

		methods.AddTokenRequiredMethod(method)
	}

	// Validate and add appID required methods
	for _, method := range cfg.Service.AppIDRequiredMethods {
		if err := validateMethodFormat(method); err != nil {
			return nil, fmt.Errorf("invalid appID required method format: %w", err)
		}

		methods.AddAppIDRequiredMethod(method)
	}

	return methods, nil
}

func (m *Methods) AddTokenRequiredMethod(method string) {
	m.tokenRequiredMethods[method] = true
}

func (m *Methods) AddAppIDRequiredMethod(method string) {
	m.appIDRequiredMethods[method] = true
}

func (m *Methods) IsTokenRequired(method string) bool {
	return m.tokenRequiredMethods[method]
}

func (m *Methods) IsAppIDRequired(method string) bool {
	return m.appIDRequiredMethods[method]
}

func validateMethodFormat(method string) error {
	if !strings.HasPrefix(method, "/") || strings.Count(method, "/") != 2 {
		return fmt.Errorf("invalid public method format: %s", method)
	}
	return nil
}
