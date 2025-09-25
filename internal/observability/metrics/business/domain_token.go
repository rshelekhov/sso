package business

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	MetricTokenIssued             = "token.issued.total"
	MetricTokenValidated          = "token.validated.total"
	MetricTokenRevoked            = "token.revoked.total"
	MetricTokenValidationDuration = "token.validation.duration.seconds"
	MetricJWKSCacheOperations     = "jwks.cache.operations.total"
	MetricKeyGenerationDuration   = "key.generation.duration.seconds"
)

type TokenMetrics struct {
	// Token operations
	TokenIssued             metric.Int64Counter
	TokenValidated          metric.Int64Counter
	TokenRevoked            metric.Int64Counter
	TokenValidationDuration metric.Float64Histogram

	// Key management
	JWKSCacheOperations   metric.Int64Counter
	KeyGenerationDuration metric.Float64Histogram
}

func newTokenMetrics(meter metric.Meter) (*TokenMetrics, error) {
	var err error
	metrics := &TokenMetrics{}

	if metrics.TokenIssued, err = createCounter(
		meter,
		MetricTokenIssued,
		"Tokens issued by type and result",
		"{token}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricTokenIssued, err)
	}

	if metrics.TokenValidated, err = createCounter(
		meter,
		MetricTokenValidated,
		"Token validation attempts by result",
		"{attempt}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricTokenValidated, err)
	}

	if metrics.TokenRevoked, err = createCounter(
		meter,
		MetricTokenRevoked,
		"Revoked tokens by reason",
		"{token}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricTokenRevoked, err)
	}

	if metrics.TokenValidationDuration, err = createHistogram(
		meter,
		MetricTokenValidationDuration,
		"Token validation time",
		"s",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricTokenValidationDuration, err)
	}

	if metrics.JWKSCacheOperations, err = createCounter(
		meter,
		MetricJWKSCacheOperations,
		"JWKS cache operations by result",
		"{operation}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricJWKSCacheOperations, err)
	}

	if metrics.KeyGenerationDuration, err = createHistogram(
		meter,
		MetricKeyGenerationDuration,
		"Key generation time by algorithm",
		"s",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricKeyGenerationDuration, err)
	}

	return metrics, nil
}

// Token issuance
func (m *TokenMetrics) RecordAccessTokenIssued(ctx context.Context, clientID string) {
	m.TokenIssued.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("token.type", "access"),
			attribute.String("result", "success"),
		),
	)
}

func (m *TokenMetrics) RecordRefreshTokenIssued(ctx context.Context, clientID string) {
	m.TokenIssued.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("token.type", "refresh"),
			attribute.String("result", "success"),
		),
	)
}

func (m *TokenMetrics) RecordAccessTokenIssueFailed(ctx context.Context, clientID string) {
	m.TokenIssued.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("token.type", "access"),
			attribute.String("result", "failure"),
		),
	)
}

// Token validation
func (m *TokenMetrics) RecordTokenValidationSuccess(ctx context.Context, clientID string) {
	m.TokenValidated.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("result", "success"),
		),
	)
}

func (m *TokenMetrics) RecordTokenValidationExpired(ctx context.Context, clientID string) {
	m.TokenValidated.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("result", "expired"),
		),
	)
}

func (m *TokenMetrics) RecordTokenValidationInvalid(ctx context.Context, clientID string) {
	m.TokenValidated.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("result", "invalid"),
		),
	)
}

func (m *TokenMetrics) RecordTokenValidationMalformed(ctx context.Context, clientID string) {
	m.TokenValidated.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("result", "malformed"),
		),
	)
}

// Token revocation
func (m *TokenMetrics) RecordTokenRevokedLogout(ctx context.Context, clientID string) {
	m.TokenRevoked.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("reason", "logout"),
		),
	)
}

func (m *TokenMetrics) RecordTokenRevokedExpired(ctx context.Context, clientID string) {
	m.TokenRevoked.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("reason", "expired"),
		),
	)
}

func (m *TokenMetrics) RecordTokenRevokedSecurity(ctx context.Context, clientID string) {
	m.TokenRevoked.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("reason", "security"),
		),
	)
}

func (m *TokenMetrics) RecordTokenValidationDuration(ctx context.Context, clientID string, duration float64) {
	m.TokenValidationDuration.Record(ctx, duration,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

// JWKS operations
func (m *TokenMetrics) RecordJWKSCacheHit(ctx context.Context, clientID string) {
	m.JWKSCacheOperations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("result", "hit"),
		),
	)
}

func (m *TokenMetrics) RecordJWKSCacheMiss(ctx context.Context, clientID string) {
	m.JWKSCacheOperations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("result", "miss"),
		),
	)
}

// Key generation duration
func (m *TokenMetrics) RecordPrivateKeyPEMGenerationDuration(ctx context.Context, clientID string, duration float64) {
	m.KeyGenerationDuration.Record(ctx, duration,
		metric.WithAttributes(
			attribute.String("client.ID", clientID),
			attribute.String("algorithm", "RSA"),
		),
	)
}
