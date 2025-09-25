package auth

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
)

type (
	MetricsRecorder interface {
		RecordLoginAttempt(ctx context.Context, clientID string)
		RecordLoginSuccess(ctx context.Context, clientID string)
		RecordLoginError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)

		RecordRegistrationAttempt(ctx context.Context, clientID string)
		RecordRegistrationSuccess(ctx context.Context, clientID string)
		RecordRegistrationError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)

		RecordPasswordResetAttempt(ctx context.Context, clientID string)
		RecordPasswordResetSuccess(ctx context.Context, clientID string)
		RecordPasswordResetError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)

		RecordChangePasswordAttempt(ctx context.Context, clientID string)
		RecordChangePasswordSuccess(ctx context.Context, clientID string)
		RecordChangePasswordError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)

		RecordEmailVerificationAttempt(ctx context.Context)
		RecordEmailVerificationSuccess(ctx context.Context)
		RecordEmailVerificationError(ctx context.Context, attrs ...attribute.KeyValue)

		RecordLogoutAttempt(ctx context.Context, clientID string)
		RecordLogoutSuccess(ctx context.Context, clientID string)
		RecordLogoutError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)

		RecordRefreshTokensAttempt(ctx context.Context, clientID string)
		RecordRefreshTokensSuccess(ctx context.Context, clientID string)
		RecordRefreshTokensError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)

		RecordJWKSRetrievalAttempt(ctx context.Context, clientID string)
		RecordJWKSRetrievalSuccess(ctx context.Context, clientID string)
		RecordJWKSRetrievalError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)

		RecordSessionExpired(ctx context.Context, clientID string)
	}

	TokenMetricsRecorder interface {
		RecordTokenRevokedLogout(ctx context.Context, clientID string)
	}
)
