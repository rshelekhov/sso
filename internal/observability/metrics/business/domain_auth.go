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
	metrics := &AuthMetrics{}

	if err := createLoginMetrics(meter, metrics); err != nil {
		return nil, err
	}

	if err := createRegistrationMetrics(meter, metrics); err != nil {
		return nil, err
	}

	if err := createPasswordMetrics(meter, metrics); err != nil {
		return nil, err
	}

	if err := createEmailVerificationMetrics(meter, metrics); err != nil {
		return nil, err
	}

	if err := createLogoutMetrics(meter, metrics); err != nil {
		return nil, err
	}

	if err := createRefreshTokensMetrics(meter, metrics); err != nil {
		return nil, err
	}

	if err := createJWKSMetrics(meter, metrics); err != nil {
		return nil, err
	}

	if err := createSessionMetrics(meter, metrics); err != nil {
		return nil, err
	}

	return metrics, nil
}

func createLoginMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	if metrics.LoginAttempts, err = createCounter(
		meter,
		MetricLoginAttempts,
		"Login attempts by result and client",
		"{attempt}",
	); err != nil {
		return fmt.Errorf("failed to create login attempts counter: %w", err)
	}

	if metrics.LoginSuccess, err = createCounter(
		meter,
		MetricLoginSuccess,
		"Login success by client",
		"{success}",
	); err != nil {
		return fmt.Errorf("failed to create login success counter: %w", err)
	}

	if metrics.LoginErrors, err = createCounter(
		meter,
		MetricLoginErrors,
		"Login errors by client",
		"{error}",
	); err != nil {
		return fmt.Errorf("failed to create login errors counter: %w", err)
	}

	return nil
}

func createRegistrationMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	if metrics.RegistrationAttempts, err = createCounter(
		meter,
		MetricRegistrationAttempts,
		"User registration attempts by result",
		"{attempt}",
	); err != nil {
		return fmt.Errorf("failed to create registration attempts counter: %w", err)
	}

	if metrics.RegistrationSuccess, err = createCounter(
		meter,
		MetricRegistrationSuccess,
		"User registration successes by result",
		"{success}",
	); err != nil {
		return fmt.Errorf("failed to create registration success counter: %w", err)
	}

	if metrics.RegistrationErrors, err = createCounter(
		meter,
		MetricRegistrationErrors,
		"User registration errors by result",
		"{error}",
	); err != nil {
		return fmt.Errorf("failed to create registration errors counter: %w", err)
	}

	return nil
}

func createPasswordMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	// Password reset metrics
	if metrics.PasswordResetsAttempts, err = createCounter(
		meter,
		MetricPasswordResetsAttempts,
		"Password reset attempts by result",
		"{attempt}",
	); err != nil {
		return fmt.Errorf("failed to create password reset attempts counter: %w", err)
	}

	if metrics.PasswordResetsSuccess, err = createCounter(
		meter,
		MetricPasswordResetsSuccess,
		"Password reset successes by result",
		"{success}",
	); err != nil {
		return fmt.Errorf("failed to create password reset success counter: %w", err)
	}

	if metrics.PasswordResetsErrors, err = createCounter(
		meter,
		MetricPasswordResetsErrors,
		"Password reset errors by result",
		"{error}",
	); err != nil {
		return fmt.Errorf("failed to create password reset errors counter: %w", err)
	}

	// Change password metrics
	if metrics.ChangePasswordAttempts, err = createCounter(
		meter,
		MetricChangePasswordAttempts,
		"Change password attempts by result",
		"{attempt}",
	); err != nil {
		return fmt.Errorf("failed to create change password attempts counter: %w", err)
	}

	if metrics.ChangePasswordSuccess, err = createCounter(
		meter,
		MetricChangePasswordSuccess,
		"Change password successes by result",
		"{success}",
	); err != nil {
		return fmt.Errorf("failed to create change password success counter: %w", err)
	}

	if metrics.ChangePasswordErrors, err = createCounter(
		meter,
		MetricChangePasswordErrors,
		"Change password errors by result",
		"{error}",
	); err != nil {
		return fmt.Errorf("failed to create change password errors counter: %w", err)
	}

	return nil
}

func createEmailVerificationMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	if metrics.EmailVerificationsAttempts, err = createCounter(
		meter,
		MetricEmailVerificationsAttempts,
		"Email verification attempts by result",
		"{attempt}",
	); err != nil {
		return fmt.Errorf("failed to create email verification attempts counter: %w", err)
	}

	if metrics.EmailVerificationSuccess, err = createCounter(
		meter,
		MetricEmailVerificationSuccess,
		"Email verification successes by result",
		"{success}",
	); err != nil {
		return fmt.Errorf("failed to create email verification success counter: %w", err)
	}

	if metrics.EmailVerificationErrors, err = createCounter(
		meter,
		MetricEmailVerificationErrors,
		"Email verification errors by result",
		"{error}",
	); err != nil {
		return fmt.Errorf("failed to create email verification errors counter: %w", err)
	}

	return nil
}

func createLogoutMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	if metrics.LogoutAttempts, err = createCounter(
		meter,
		MetricLogoutAttempts,
		"Logout operations by result",
		"{operation}",
	); err != nil {
		return fmt.Errorf("failed to create logout attempts counter: %w", err)
	}

	if metrics.LogoutSuccess, err = createCounter(
		meter,
		MetricLogoutSuccess,
		"Logout operations by result",
		"{operation}",
	); err != nil {
		return fmt.Errorf("failed to create logout success counter: %w", err)
	}

	if metrics.LogoutErrors, err = createCounter(
		meter,
		MetricLogoutErrors,
		"Logout operations by result",
		"{operation}",
	); err != nil {
		return fmt.Errorf("failed to create logout errors counter: %w", err)
	}

	return nil
}

func createRefreshTokensMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	if metrics.RefreshTokensAttempts, err = createCounter(
		meter,
		MetricRefreshTokensAttempts,
		"Refresh tokens attempts by result",
		"{attempt}",
	); err != nil {
		return fmt.Errorf("failed to create refresh tokens attempts counter: %w", err)
	}

	if metrics.RefreshTokensSuccess, err = createCounter(
		meter,
		MetricRefreshTokensSuccess,
		"Refresh tokens successes by result",
		"{success}",
	); err != nil {
		return fmt.Errorf("failed to create refresh tokens success counter: %w", err)
	}

	if metrics.RefreshTokensErrors, err = createCounter(
		meter,
		MetricRefreshTokensErrors,
		"Refresh tokens errors by result",
		"{error}",
	); err != nil {
		return fmt.Errorf("failed to create refresh tokens errors counter: %w", err)
	}

	return nil
}

func createJWKSMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	if metrics.MetricJWKSRetrievalAttempts, err = createCounter(
		meter,
		MetricJWKSRetrievalAttempts,
		"JWKS retrieval attempts by result",
		"{attempt}",
	); err != nil {
		return fmt.Errorf("failed to create JWKS retrieval attempts counter: %w", err)
	}

	if metrics.MetricJWKSRetrievalSuccess, err = createCounter(
		meter,
		MetricJWKSRetrievalSuccess,
		"JWKS retrieval successes by result",
		"{success}",
	); err != nil {
		return fmt.Errorf("failed to create JWKS retrieval success counter: %w", err)
	}

	if metrics.MetricJWKSRetrievalErrors, err = createCounter(
		meter,
		MetricJWKSRetrievalErrors,
		"JWKS retrieval errors by result",
		"{error}",
	); err != nil {
		return fmt.Errorf("failed to create JWKS retrieval errors counter: %w", err)
	}

	return nil
}

func createSessionMetrics(meter metric.Meter, metrics *AuthMetrics) error {
	var err error

	if metrics.SessionExpired, err = createCounter(
		meter,
		MetricSessionExpired,
		"Sessions expired by reason",
		"{session}",
	); err != nil {
		return fmt.Errorf("failed to create session expired counter: %w", err)
	}

	return nil
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
