package business

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

type Metrics struct {
	Auth    *AuthMetrics
	Client  *ClientMetrics
	User    *UserMetrics
	Session *SessionMetrics
	Token   *TokenMetrics
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	const op = "business.NewMetrics"

	auth, err := newAuthMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create auth metrics: %w", op, err)
	}

	client, err := newClientMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create client metrics: %w", op, err)
	}

	user, err := newUserMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create user metrics: %w", op, err)
	}

	session, err := newSessionMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create session metrics: %w", op, err)
	}

	token, err := newTokenMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create token metrics: %w", op, err)
	}

	return &Metrics{
		Auth:    auth,
		Client:  client,
		User:    user,
		Session: session,
		Token:   token,
	}, nil
}

// NewNoOpMetrics creates a metrics instance with all NoOp implementations
func NewNoOpMetrics() *Metrics {
	// Use OpenTelemetry's NoOp meter to create proper NoOp instruments
	noopMeter := noop.NewMeterProvider().Meter("")

	// Create metrics with NoOp instruments - these will not panic when called
	auth, _ := newAuthMetrics(noopMeter)
	client, _ := newClientMetrics(noopMeter)
	user, _ := newUserMetrics(noopMeter)
	session, _ := newSessionMetrics(noopMeter)
	token, _ := newTokenMetrics(noopMeter)

	return &Metrics{
		Auth:    auth,
		Client:  client,
		User:    user,
		Session: session,
		Token:   token,
	}
}
