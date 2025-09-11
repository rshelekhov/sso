package metrics

import (
	"fmt"

	"github.com/rshelekhov/sso/internal/observability/metrics/business"
	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"
	"go.opentelemetry.io/otel/metric"
)

// Registry contains only centralized infrastructure and business metrics
// Domain-specific metrics are created and injected directly into their respective services
type Registry struct {
	Infrastructure *infrastructure.Metrics
	Business       *business.Metrics
}

func NewRegistry(meter metric.Meter) (*Registry, error) {
	infrastructure, err := infrastructure.NewMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create infrastructure metrics: %w", err)
	}

	business, err := business.NewMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create business metrics: %w", err)
	}

	return &Registry{
		Infrastructure: infrastructure,
		Business:       business,
	}, nil
}
