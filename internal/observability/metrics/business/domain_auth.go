package business

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	MetricLoginAttempts = "auth.login.attempts.total"
	MetricLoginSuccess  = "auth.login.success.total"
	MetricLoginErrors   = "auth.login.errors.total"

	MetricRegistrationAttempts = "auth.registration.attempts.total"
	MetricRegistrationSuccess  = "auth.registration.success.total"
	MetricRegistrationErrors   = "auth.registration.errors.total"

	MetricPasswordResetsAttempts = "auth.password.reset.attempts.total"
	MetricPasswordResetsSuccess  = "auth.password.reset.success.total"
	MetricPasswordResetsErrors   = "auth.password.reset.errors.total"

	MetricChangePasswordAttempts = "auth.change.password.attempts.total"
	MetricChangePasswordSuccess  = "auth.change.password.success.total"
	MetricChangePasswordErrors   = "auth.change.password.errors.total"

	MetricEmailVerificationsAttempts = "auth.email.verification.attempts.total"
	MetricEmailVerificationSuccess   = "auth.email.verification.success.total"
	MetricEmailVerificationErrors    = "auth.email.verification.errors.total"

	MetricLogoutAttempts = "auth.logout.attempts.total"
	MetricLogoutSuccess  = "auth.logout.success.total"
	MetricLogoutErrors   = "auth.logout.errors.total"

	MetricRefreshTokensAttempts = "auth.refresh.tokens.attempts.total"
	MetricRefreshTokensSuccess  = "auth.refresh.tokens.success.total"
	MetricRefreshTokensErrors   = "auth.refresh.tokens.errors.total"

	MetricJWKSRetrievalAttempts = "auth.jwks.retrieval.attempts.total"
	MetricJWKSRetrievalSuccess  = "auth.jwks.retrieval.success.total"
	MetricJWKSRetrievalErrors   = "auth.jwks.retrieval.errors.total"

	MetricSessionExpired = "auth.session.expired.total"
)

type AuthMetrics struct {
	// Operational metrics - what operations happen
	LoginAttempts metric.Int64Counter
	LoginSuccess  metric.Int64Counter
	LoginErrors   metric.Int64Counter

	RegistrationAttempts metric.Int64Counter
	RegistrationSuccess  metric.Int64Counter
	RegistrationErrors   metric.Int64Counter

	PasswordResetsAttempts metric.Int64Counter
	PasswordResetsSuccess  metric.Int64Counter
	PasswordResetsErrors   metric.Int64Counter

	ChangePasswordAttempts metric.Int64Counter
	ChangePasswordSuccess  metric.Int64Counter
	ChangePasswordErrors   metric.Int64Counter

	EmailVerificationsAttempts metric.Int64Counter
	EmailVerificationSuccess   metric.Int64Counter
	EmailVerificationErrors    metric.Int64Counter

	LogoutAttempts metric.Int64Counter
	LogoutSuccess  metric.Int64Counter
	LogoutErrors   metric.Int64Counter

	RefreshTokensAttempts metric.Int64Counter
	RefreshTokensSuccess  metric.Int64Counter
	RefreshTokensErrors   metric.Int64Counter

	MetricJWKSRetrievalAttempts metric.Int64Counter
	MetricJWKSRetrievalSuccess  metric.Int64Counter
	MetricJWKSRetrievalErrors   metric.Int64Counter

	SessionExpired metric.Int64Counter

	// Future metrics
	// DailyActiveUsers metric.Int64UpDownCounter
	// AuthSuccessRate metric.Float64Gauge
	// SuspiciousActivity metric.Int64Counter
	// PasswordStrengthScore metric.Float64Histogram
}

func newAuthMetrics(meter metric.Meter) (*AuthMetrics, error) {
	// Login metrics
	loginAttempts, err := meter.Int64Counter(
		MetricLoginAttempts,
		metric.WithDescription("Login attempts by result and client"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create login attempts counter: %w", err)
	}

	loginSuccess, err := meter.Int64Counter(
		MetricLoginSuccess,
		metric.WithDescription("Login success by client"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create login success counter: %w", err)
	}

	loginErrors, err := meter.Int64Counter(
		MetricLoginErrors,
		metric.WithDescription("Login errors by client"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create login errors counter: %w", err)
	}

	// Registration metrics
	registrationAttempts, err := meter.Int64Counter(
		MetricRegistrationAttempts,
		metric.WithDescription("User registration attempts by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registrations counter: %w", err)
	}

	registrationSuccess, err := meter.Int64Counter(
		MetricRegistrationSuccess,
		metric.WithDescription("User registration successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registrations counter: %w", err)
	}

	registrationErrors, err := meter.Int64Counter(
		MetricRegistrationErrors,
		metric.WithDescription("User registration errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registrations counter: %w", err)
	}

	// Password reset metrics
	passwordResetsAttempts, err := meter.Int64Counter(
		MetricPasswordResetsAttempts,
		metric.WithDescription("Password reset attempts by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create password resets counter: %w", err)
	}

	passwordResetsSuccess, err := meter.Int64Counter(
		MetricPasswordResetsSuccess,
		metric.WithDescription("Password reset successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create password resets counter: %w", err)
	}

	passwordResetsErrors, err := meter.Int64Counter(
		MetricPasswordResetsErrors,
		metric.WithDescription("Password reset errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create password resets counter: %w", err)
	}

	// Change password metrics

	changePasswordAttempts, err := meter.Int64Counter(
		MetricChangePasswordAttempts,
		metric.WithDescription("Change password attempts by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create change password counter: %w", err)
	}

	changePasswordSuccess, err := meter.Int64Counter(
		MetricChangePasswordSuccess,
		metric.WithDescription("Change password successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create change password counter: %w", err)
	}

	changePasswordErrors, err := meter.Int64Counter(
		MetricChangePasswordErrors,
		metric.WithDescription("Change password errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create change password counter: %w", err)
	}

	// Email verification metrics
	emailVerifications, err := meter.Int64Counter(
		MetricEmailVerificationsAttempts,
		metric.WithDescription("Email verification attempts by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create email verifications counter: %w", err)
	}
	emailVerificationSuccess, err := meter.Int64Counter(
		MetricEmailVerificationSuccess,
		metric.WithDescription("Email verification successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create email verifications counter: %w", err)
	}
	emailVerificationErrors, err := meter.Int64Counter(
		MetricEmailVerificationErrors,
		metric.WithDescription("Email verification errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create email verifications counter: %w", err)
	}

	// Logout metrics
	logoutAttempts, err := meter.Int64Counter(
		MetricLogoutAttempts,
		metric.WithDescription("Logout operations by result"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create logout operations counter: %w", err)
	}

	logoutSuccess, err := meter.Int64Counter(
		MetricLogoutSuccess,
		metric.WithDescription("Logout operations by result"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create logout operations counter: %w", err)
	}

	logoutErrors, err := meter.Int64Counter(
		MetricLogoutErrors,
		metric.WithDescription("Logout operations by result"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create logout operations counter: %w", err)
	}

	// Refresh tokens metrics

	refreshTokensAttempts, err := meter.Int64Counter(
		MetricRefreshTokensAttempts,
		metric.WithDescription("Refresh tokens attempts by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh tokens counter: %w", err)
	}
	refreshTokensSuccess, err := meter.Int64Counter(
		MetricRefreshTokensSuccess,
		metric.WithDescription("Refresh tokens successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh tokens counter: %w", err)
	}
	refreshTokensErrors, err := meter.Int64Counter(
		MetricRefreshTokensErrors,
		metric.WithDescription("Refresh tokens errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh tokens counter: %w", err)
	}

	// JWKS retrieval metrics

	jwksRetrievalAttempts, err := meter.Int64Counter(
		MetricJWKSRetrievalAttempts,
		metric.WithDescription("JWKS retrieval attempts by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwks retrieval counter: %w", err)
	}

	jwksRetrievalSuccess, err := meter.Int64Counter(
		MetricJWKSRetrievalSuccess,
		metric.WithDescription("JWKS retrieval successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwks retrieval counter: %w", err)
	}

	jwksRetrievalErrors, err := meter.Int64Counter(
		MetricJWKSRetrievalErrors,
		metric.WithDescription("JWKS retrieval errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwks retrieval counter: %w", err)
	}

	// Session metrics
	sessionExpired, err := meter.Int64Counter(
		MetricSessionExpired,
		metric.WithDescription("Sessions expired by reason"),
		metric.WithUnit("{session}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session expired counter: %w", err)
	}

	return &AuthMetrics{
		LoginAttempts:               loginAttempts,
		LoginSuccess:                loginSuccess,
		LoginErrors:                 loginErrors,
		RegistrationAttempts:        registrationAttempts,
		RegistrationSuccess:         registrationSuccess,
		RegistrationErrors:          registrationErrors,
		PasswordResetsAttempts:      passwordResetsAttempts,
		PasswordResetsSuccess:       passwordResetsSuccess,
		PasswordResetsErrors:        passwordResetsErrors,
		ChangePasswordAttempts:      changePasswordAttempts,
		ChangePasswordSuccess:       changePasswordSuccess,
		ChangePasswordErrors:        changePasswordErrors,
		EmailVerificationsAttempts:  emailVerifications,
		EmailVerificationSuccess:    emailVerificationSuccess,
		EmailVerificationErrors:     emailVerificationErrors,
		LogoutAttempts:              logoutAttempts,
		LogoutSuccess:               logoutSuccess,
		LogoutErrors:                logoutErrors,
		RefreshTokensAttempts:       refreshTokensAttempts,
		RefreshTokensSuccess:        refreshTokensSuccess,
		RefreshTokensErrors:         refreshTokensErrors,
		MetricJWKSRetrievalAttempts: jwksRetrievalAttempts,
		MetricJWKSRetrievalSuccess:  jwksRetrievalSuccess,
		MetricJWKSRetrievalErrors:   jwksRetrievalErrors,
		SessionExpired:              sessionExpired,
	}, nil
}

func (m *AuthMetrics) RecordLoginAttempt(ctx context.Context, clientID string) {
	m.LoginAttempts.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *AuthMetrics) RecordLoginSuccess(ctx context.Context, clientID string) {
	m.LoginSuccess.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *AuthMetrics) RecordLoginError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.LoginErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordRegistrationAttempt(ctx context.Context, clientID string) {
	m.RegistrationAttempts.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *AuthMetrics) RecordRegistrationSuccess(ctx context.Context, clientID string) {
	m.RegistrationSuccess.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *AuthMetrics) RecordRegistrationError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.RegistrationErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordPasswordResetAttempt(ctx context.Context, clientID string) {
	m.PasswordResetsAttempts.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *AuthMetrics) RecordPasswordResetSuccess(ctx context.Context, clientID string) {
	m.PasswordResetsSuccess.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordPasswordResetError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.PasswordResetsErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordChangePasswordAttempt(ctx context.Context, clientID string) {
	m.ChangePasswordAttempts.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *AuthMetrics) RecordChangePasswordSuccess(ctx context.Context, clientID string) {
	m.ChangePasswordSuccess.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordChangePasswordError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.ChangePasswordErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordEmailVerificationAttempt(ctx context.Context) {
	m.EmailVerificationsAttempts.Add(ctx, 1)
}

func (m *AuthMetrics) RecordEmailVerificationSuccess(ctx context.Context) {
	m.EmailVerificationSuccess.Add(ctx, 1)
}

func (m *AuthMetrics) RecordEmailVerificationError(ctx context.Context, attrs ...attribute.KeyValue) {
	m.EmailVerificationErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordLogoutAttempt(ctx context.Context, clientID string) {
	m.LogoutAttempts.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordLogoutSuccess(ctx context.Context, clientID string) {
	m.LogoutSuccess.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordLogoutError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.LogoutErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordRefreshTokensAttempt(ctx context.Context, clientID string) {
	m.RefreshTokensAttempts.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordRefreshTokensSuccess(ctx context.Context, clientID string) {
	m.RefreshTokensSuccess.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordRefreshTokensError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.RefreshTokensErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordJWKSRetrievalAttempt(ctx context.Context, clientID string) {
	m.MetricJWKSRetrievalAttempts.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordJWKSRetrievalSuccess(ctx context.Context, clientID string) {
	m.MetricJWKSRetrievalSuccess.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *AuthMetrics) RecordJWKSRetrievalError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.MetricJWKSRetrievalErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *AuthMetrics) RecordSessionExpired(ctx context.Context, clientID string) {
	m.SessionExpired.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}
