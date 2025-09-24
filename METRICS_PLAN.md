# SSO Service Metrics Implementation Plan

## Overview

This document outlines the comprehensive metrics implementation plan for the SSO service. The approach follows a hybrid model with centralized common metrics and domain-specific metrics for better organization and maintainability.

## Metrics Categories

### 1. Infrastructure Metrics (Centralized)

**Location**: `internal/observability/metrics/infrastructure.go`

#### gRPC Transport

- `rpc.requests.total` (Counter) - Total RPC requests by method, status
- `rpc.active.connections` (UpDownCounter) - Active RPC connections
- `rpc.server.duration` (Histogram) - Server-side request duration by method
- `rpc.server.request.size` (Histogram) - Server-side request size by method
- `rpc.server.response.size` (Histogram) - Server-side response size by method

Also check this – https://opentelemetry.io/docs/specs/semconv/rpc/rpc-metrics/

#### System Resources

- `db.client.operation.duration` (Histogram) - DB client operation duration
- `db.client.operation.count` (Counter) - DB client operation count
- `db.client.operation.error` (Counter) - DB client operation error count
- `db.client.connection.count` (UpDownCounter) - DB client connection count
- `db.client.connection.idle.max` (UpDownCounter) - DB client connection idle max
- `db.client.connection.idle.min` (UpDownCounter) - DB client connection idle min
- `db.client.connection.max` (UpDownCounter) - DB client connection max
- `db.client.connection.min` (UpDownCounter) - DB client connection min
- `redis.operation.duration` (Histogram) - Redis operation duration
- `redis.operation.count` (Counter) - Redis operation count
- `redis.operation.error` (Counter) - Redis operation error count
- `redis.connection.pool.active` (UpDownCounter) - Redis connection pool active count
- `redis.connection.pool.wait_duration` (Histogram) - Redis connection pool wait duration
- `s3.operation.duration` (Histogram) - S3 operation duration
- `s3.operation.count` (Counter) - S3 operation count
- `s3.operation.error` (Counter) - S3 operation error count
- `s3.http.request.duration` (Histogram) - S3 HTTP request duration

### 2. Authentication Metrics (Domain-specific)

**Location**: `internal/domain/usecase/auth/metrics.go`

Each domain defines its own metrics structure:

```go
// internal/domain/usecase/auth/metrics.go
package auth

import "go.opentelemetry.io/otel/metric"

type Metrics struct {
    LoginAttempts         metric.Int64Counter
    Registrations         metric.Int64Counter
    PasswordResets        metric.Int64Counter
    EmailVerifications    metric.Int64Counter
    LogoutOperations      metric.Int64Counter
    SuspiciousActivity    metric.Int64Counter
    PasswordStrengthScore metric.Float64Histogram
}

func NewMetrics(meter metric.Meter) *Metrics {
    return &Metrics{
        LoginAttempts: meter.Int64Counter("auth.login.attempts.total"),
        Registrations: meter.Int64Counter("auth.registration.attempts.total"),
        PasswordResets: meter.Int64Counter("auth.password.reset.attempts.total"),
        EmailVerifications: meter.Int64Counter("auth.email.verification.attempts.total"),
        LogoutOperations: meter.Int64Counter("auth.logout.operations.total"),
        SuspiciousActivity: meter.Int64Counter("auth.suspicious.activity.total"),
        PasswordStrengthScore: meter.Float64Histogram("auth.password.strength.score"),
    }
}
```

#### Core Auth Operations

- `auth.login.attempts.total` (Counter) - Login attempts by result (success/failure/invalid_credentials/timeout)
- `auth.registration.attempts.total` (Counter) - User registrations by result (success/failure/email_exists)
- `auth.password.reset.attempts.total` (Counter) - Password reset requests by result (success/failure/user_not_found)
- `auth.email.verification.attempts.total` (Counter) - Email verification attempts by result (success/failure/expired/invalid)
- `auth.logout.operations.total` (Counter) - Logout operations by result (success/failure)

### 3. Session Management Metrics (Domain-specific)

**Location**: `internal/domain/service/session/metrics.go`

#### Session Lifecycle

- `session.active.total` (UpDownCounter) - Active sessions by client
- `session.created.total` (Counter) - Sessions created by result (success/failure)
- `session.expired.total` (Counter) - Sessions expired by reason (natural/forced/timeout/revoked)
- `session.refresh.attempts.total` (Counter) - Token refresh attempts by result (success/failure/expired/invalid)
- `session.duration.seconds` (Histogram) - Session lifetime distribution

#### Device Management

- `user.devices.active` (UpDownCounter) - Active devices per user
- `device.registrations.total` (Counter) - New device registrations
- `device.cleanup.operations.total` (Counter) - Device cleanup operations

### 4. Token Management Metrics (Domain-specific)

**Location**: `internal/domain/service/token/metrics.go`

#### Token Operations

- `token.issued.total` (Counter) - Tokens issued by type (access/refresh) and result (success/failure)
- `token.validated.total` (Counter) - Token validation attempts by result (success/failure/expired/invalid/malformed)
- `token.revoked.total` (Counter) - Revoked tokens by reason (logout/expired/security/admin)
- `token_validation_duration_seconds` (Histogram) - Token validation time

#### Key Management

- `jwks.rotations.total` (Counter) - JWKS key rotations by result (success/failure)
- `jwks.cache.operations.total` (Counter) - JWKS cache operations by result (hit/miss)
- `key.generation.duration.seconds` (Histogram) - Key generation time by algorithm

### 5. User Management Metrics (Domain-specific)

**Location**: `internal/domain/usecase/user/metrics.go`

#### User Operations

- `user.total` (UpDownCounter) - Total users by status (active/inactive/deleted)
- `user.profile.updates.total` (Counter) - Profile update operations by result (success/failure/validation_error)
- `user.deletions.total` (Counter) - User deletion operations by result (success/failure) and type (soft/hard)
- `user.verification.status.changes.total` (Counter) - Verification status changes by transition (pending_to_verified/verified_to_pending)

### 6. Client Management Metrics (Domain-specific)

**Location**: `internal/domain/usecase/client/metrics.go`

#### Multi-tenancy

- `client.registered.total` (Counter) - Registered clients by result (success/failure/already_exists)
- `client.operations.total` (Counter) - Client operations by type (create/update/delete) and result (success/failure)
- `client.validation.attempts.total` (Counter) - Client validation attempts by result (success/failure/not_found/invalid)

### 7. Business Intelligence Metrics (Centralized)

**Location**: `internal/observability/metrics/business.go`

#### Usage Analytics

- `user.daily.active` (UpDownCounter) - Daily active users by client
- `user.retention.rate` (Gauge) - User retention metrics
- `feature.usage.total` (Counter) - Feature usage by type
- `api.usage.by.client.total` (Counter) - API usage per client

#### Performance KPIs

- `auth.success.rate` (Gauge) - Auth success rate percentage
- `session.duration.average.seconds` (Gauge) - Average session duration
- `system.availability.percentage` (Gauge) - System uptime percentage

## Implementation Structure

### Metrics Registry

**Location**: `internal/observability/metrics/registry.go`

```go
package metrics

import (
    authMetrics "github.com/rshelekhov/sso/internal/domain/usecase/auth"
    userMetrics "github.com/rshelekhov/sso/internal/domain/usecase/user"
    clientMetrics "github.com/rshelekhov/sso/internal/domain/usecase/client"
    sessionMetrics "github.com/rshelekhov/sso/internal/domain/service/session"
    tokenMetrics "github.com/rshelekhov/sso/internal/domain/service/token"
    "go.opentelemetry.io/otel/metric"
)

type Registry struct {
    Infrastructure *InfrastructureMetrics  // Remains in this package
    Business       *BusinessMetrics        // Remains in this package
    Auth           *authMetrics.Metrics
    User           *userMetrics.Metrics
    Client         *clientMetrics.Metrics
    Session        *sessionMetrics.Metrics
    Token          *tokenMetrics.Metrics
}

func NewRegistry(meter metric.Meter) *Registry {
    return &Registry{
        Infrastructure: NewInfrastructureMetrics(meter),
        Business:       NewBusinessMetrics(meter),
        Auth:           authMetrics.NewMetrics(meter),
        User:           userMetrics.NewMetrics(meter),
        Client:         clientMetrics.NewMetrics(meter),
        Session:        sessionMetrics.NewMetrics(meter),
        Token:          tokenMetrics.NewMetrics(meter),
    }
}
```

### Integration Points

#### 1. gRPC Interceptor Level

**Location**: `internal/lib/interceptor/metrics/`

- Request counting and timing
- Error rate tracking
- Connection monitoring

#### 2. Use Case Level

**Location**: Each usecase package

- Business operation metrics
- Domain-specific counters
- Success/failure rates

#### 3. Service Level

**Location**: Each domain service package

- Service-specific metrics
- Internal operation tracking
- Performance monitoring

#### 4. Storage Level

**Location**: `internal/infrastructure/storage/metrics.go`

- Database operation metrics
- Connection pool monitoring
- Query performance tracking

## Implementation Phases

### Phase 1: Infrastructure Foundation

1. Create metrics registry and base infrastructure
2. Implement gRPC interceptor metrics
3. Add basic storage operation metrics
4. Set up metrics export to OTEL collector

### Phase 2: Core Authentication Metrics

1. Implement auth usecase metrics
2. Add session management metrics
3. Implement token service metrics
4. Add security-focused metrics

### Phase 3: Business Intelligence

1. Add user management metrics
2. Implement client management metrics
3. Create business intelligence dashboards
4. Add performance KPI tracking

### Phase 4: Advanced Analytics

1. Add custom business metrics
2. Implement alerting rules
3. Create performance optimization metrics
4. Add capacity planning metrics

## Grafana Dashboard Structure

### 1. System Overview Dashboard

- Infrastructure health
- Request rates and latencies
- Error rates
- Resource utilization

### 2. Authentication Dashboard

- Login success/failure rates
- Registration trends
- Security incidents
- Session analytics

### 3. Business Intelligence Dashboard

- User activity metrics
- Client usage statistics
- Feature adoption rates
- Performance KPIs

### 4. Operations Dashboard

- Database performance
- Cache hit rates
- Background job metrics
- System capacity metrics

## Configuration

### Metrics Collection

- Use OpenTelemetry metrics SDK
- Export via OTLP to collector
- Configure appropriate histogram buckets
- Set up metric labels consistently

### Alerting Rules

- High error rates (>5% for 5 minutes)
- High response times (>2s p95 for 5 minutes)
- Failed authentication spike (>100 failures in 1 minute)
- Database connection issues
- Memory/CPU usage thresholds

## Best Practices

1. **Consistent Naming**: Use snake_case with descriptive names
2. **Label Consistency**: Standardize label names across metrics
3. **Cardinality Control**: Avoid high-cardinality labels
4. **Performance**: Minimize metrics collection overhead
5. **Documentation**: Document each metric's purpose and usage
6. **Testing**: Include metrics in unit and integration tests

## Files to Create/Modify

### New Files

- `internal/observability/metrics/registry.go` - Central metrics registry
- `internal/observability/metrics/infrastructure.go` - Infrastructure metrics (gRPC, DB, Redis)
- `internal/observability/metrics/business.go` - Business intelligence metrics
- `internal/domain/usecase/auth/metrics.go` - Authentication metrics
- `internal/domain/usecase/user/metrics.go` - User management metrics
- `internal/domain/usecase/client/metrics.go` - Client management metrics
- `internal/domain/service/session/metrics.go` - Session management metrics
- `internal/domain/service/token/metrics.go` - Token management metrics
- `internal/lib/interceptor/metrics/grpc.go` - gRPC interceptor metrics

### Files to Modify

- `internal/app/builder.go` - Add metrics initialization
- `cmd/sso/main.go` - Initialize metrics registry
- All usecase files - Add metrics calls
- All service files - Add metrics calls
- Storage implementations - Add operation metrics

## Distributed Metrics Structure

### Example Implementation

Each domain package contains its own `metrics.go` file with the following structure:

```go
// internal/domain/usecase/auth/metrics.go
package auth

import "go.opentelemetry.io/otel/metric"

type Metrics struct {
    // Define domain-specific metrics here
}

func NewMetrics(meter metric.Meter) *Metrics {
    // Initialize metrics with the provided meter
}
```

### Usage in Domain Code

```go
// internal/domain/usecase/auth/auth_usecase.go
type Auth struct {
    // ... other fields
    metrics *Metrics
}

func NewUsecase(..., metrics *Metrics) *Auth {
    return &Auth{
        // ...
        metrics: metrics,
    }
}

func (u *Auth) Login(ctx context.Context, clientID string, reqData *entity.UserRequestData) (entity.SessionTokens, error) {
    // Начало попытки логина
    u.metrics.LoginAttempts.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("auth.result", "attempt"),
            attribute.String("auth.client.id", clientID),
        ))

    userData, err := u.userMgr.GetUserByEmail(ctx, reqData.Email)
    if err != nil {
        if errors.Is(err, domain.ErrUserNotFound) {
            u.metrics.LoginAttempts.Add(ctx, 1,
                metric.WithAttributes(
                    attribute.String("auth.result", "invalid_credentials"),
                    attribute.String("auth.failure.reason", "user_not_found"),
                    attribute.String("auth.client.id", clientID),
                ))
            return entity.SessionTokens{}, domain.ErrUserNotFound
        }

        u.metrics.LoginAttempts.Add(ctx, 1,
            metric.WithAttributes(
                attribute.String("auth.result", "failure"),
                attribute.String("auth.failure.reason", "database_error"),
                attribute.String("auth.client.id", clientID),
            ))
        return entity.SessionTokens{}, domain.ErrFailedToGetUserByEmail
    }

    if err = u.verifyPassword(ctx, userData, reqData.Password); err != nil {
        if errors.Is(err, domain.ErrInvalidCredentials) {
            u.metrics.LoginAttempts.Add(ctx, 1,
                metric.WithAttributes(
                    attribute.String("auth.result", "invalid_credentials"),
                    attribute.String("auth.failure.reason", "wrong_password"),
                    attribute.String("auth.client.id", clientID),
                ))
            return entity.SessionTokens{}, domain.ErrInvalidCredentials
        }

        u.metrics.LoginAttempts.Add(ctx, 1,
            metric.WithAttributes(
                attribute.String("auth.result", "failure"),
                attribute.String("auth.failure.reason", "password_verification_failed"),
                attribute.String("auth.client.id", clientID),
            ))
        return entity.SessionTokens{}, domain.ErrFailedToVerifyPassword
    }

    // Создание сессии
    tokenData, err := u.sessionMgr.CreateSession(txCtx, sessionReqData)
    if err != nil {
        u.metrics.LoginAttempts.Add(ctx, 1,
            metric.WithAttributes(
                attribute.String("auth.result", "failure"),
                attribute.String("auth.failure.reason", "session_creation_failed"),
                attribute.String("auth.client.id", clientID),
            ))
        return entity.SessionTokens{}, domain.ErrFailedToCreateUserSession
    }

    // Успешный логин
    u.metrics.LoginAttempts.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("auth.result", "success"),
            attribute.String("auth.client.id", clientID),
        ))

    return tokenData, nil
}
```

## Next Steps

1. Start with Phase 1 implementation
2. Create base metrics infrastructure and registry
3. Implement domain-specific metrics in each package
4. Add gRPC interceptor metrics
5. Test metrics collection and export
6. Move to Phase 2 with complete authentication metrics

This plan provides a comprehensive approach to metrics implementation while maintaining clean architecture principles, proper separation of concerns, and ensuring observability across all system components.
