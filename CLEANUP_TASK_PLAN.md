# Background Cleanup Task Implementation Plan for Expired Tokens and Sessions

## Task Overview

Add a background task for periodic cleanup of expired refresh tokens and sessions from Redis and database. This will improve performance and free up memory from outdated data.

## Solution Architecture

### 1. Create Cleanup Service

**File**: `internal/domain/service/cleanup/cleanup_service.go`

```go
type Service struct {
    sessionStorage    SessionStorage
    verificationStorage VerificationStorage
    metrics          MetricsRecorder
    log              *slog.Logger
}

type Config struct {
    SessionCleanupInterval     time.Duration // e.g., every 1 hour
    VerificationCleanupInterval time.Duration // e.g., every 30 minutes
    BatchSize                  int           // batch size for cleanup
}
```

### 2. Cleanup Methods

#### Session Cleanup

- Remove expired refresh tokens from Redis
- Remove related records from PostgreSQL/MongoDB
- Record `RecordTokenRevokedExpired` metric

#### Verification Token Cleanup

- Remove expired email verification tokens
- Remove expired password reset tokens

### 3. Scheduler

**File**: `internal/app/scheduler.go`

```go
type Scheduler struct {
    cleanupService *cleanup.Service
    config         cleanup.Config
    ctx            context.Context
    cancel         context.CancelFunc
}

func (s *Scheduler) Start() error
func (s *Scheduler) Stop() error
```

### 4. Application Integration

**Update**: `internal/app/app.go`

- Add Scheduler to App struct
- Start/stop together with servers

## Detailed Implementation Plan

### Stage 1: Create Interfaces and Structures

1. **Create interfaces for cleanup service**

   ```
   internal/domain/service/cleanup/interfaces.go
   ```

2. **Create metrics for cleanup operations**

   ```
   internal/domain/service/cleanup/metrics.go
   ```

3. **Add cleanup methods to storage interfaces**
   - `SessionStorage.DeleteExpiredSessions(ctx, batchSize) (int, error)`
   - `VerificationStorage.DeleteExpiredTokens(ctx, batchSize) (int, error)`

### Stage 2: Cleanup Service Implementation

1. **Main structure and constructor**

   ```
   internal/domain/service/cleanup/cleanup_service.go
   ```

2. **Cleanup methods**

   - `CleanupExpiredSessions(ctx context.Context) error`
   - `CleanupExpiredVerificationTokens(ctx context.Context) error`

3. **Logging and metrics**
   - Number of deleted records
   - Operation execution time
   - Cleanup errors

### Stage 3: Storage Layer Implementation

1. **Redis (sessions)**

   ```
   internal/infrastructure/storage/session/redis/cleanup.go
   ```

   - Search keys by pattern with expired TTL
   - Batch deletion

2. **PostgreSQL (if used)**

   ```
   internal/infrastructure/storage/session/postgres/cleanup.go
   ```

   - SQL query with WHERE expires_at < NOW()
   - LIMIT for batch processing

3. **MongoDB (if used)**
   ```
   internal/infrastructure/storage/session/mongo/cleanup.go
   ```
   - Find documents with expired expires_at
   - Batch deletion

### Stage 4: Create Scheduler

1. **Main structure**

   ```
   internal/app/scheduler.go
   ```

2. **Management methods**

   - Start() - launch goroutines with tickers
   - Stop() - graceful shutdown
   - Context cancellation handling

3. **Configuration**
   - Launch intervals
   - Batch sizes
   - Operation timeouts

### Stage 5: Application Integration

1. **Update app.go**

   - Add Scheduler to App struct
   - Initialization in New()
   - Launch in Run()
   - Stop in Stop()

2. **Update builder.go**

   - Create cleanup service
   - Pass dependencies

3. **Configuration**
   ```yaml
   cleanup:
     session_interval: "1h"
     verification_interval: "30m"
     batch_size: 1000
     enabled: true
   ```

### Stage 6: Metrics

1. **Add to TokenMetrics**

   - `RecordTokenRevokedExpired` (already exists)
   - `RecordCleanupOperationDuration`
   - `RecordCleanupRecordsDeleted`

2. **Create CleanupMetrics**
   ```
   internal/observability/metrics/business/domain_cleanup.go
   ```

### Stage 7: Testing

1. **Unit tests**

   - Cleanup service methods
   - Storage cleanup methods
   - Scheduler logic

2. **Integration tests**
   - Full cleanup cycle
   - Metrics verification
   - Graceful shutdown

## Configuration

### Parameters in config.yaml

```yaml
app:
  cleanup:
    enabled: true
    session_cleanup_interval: "1h"
    verification_cleanup_interval: "30m"
    batch_size: 1000
    operation_timeout: "5m"
```

### Environment Variables

```
CLEANUP_ENABLED=true
CLEANUP_SESSION_INTERVAL=1h
CLEANUP_VERIFICATION_INTERVAL=30m
CLEANUP_BATCH_SIZE=1000
```

## Monitoring and Alerts

### Metrics for Monitoring

1. **cleanup.sessions.deleted.total** - number of deleted sessions
2. **cleanup.verification_tokens.deleted.total** - number of deleted tokens
3. **cleanup.operation.duration.seconds** - operation execution time
4. **cleanup.errors.total** - cleanup errors

### Recommended Alerts

1. **Cleanup not running** - no metrics for the last 2 intervals
2. **High error rate** - > 5% of operations fail
3. **Slow cleanup** - operation takes > 1 minute

## Security and Performance

### Limitations

1. **Batch size** - no more than 1000 records at once
2. **Timeout** - maximum 5 minutes per operation
3. **Rate limiting** - pause between batches

### Load Monitoring

1. Track CPU/Memory during cleanup
2. Monitor main operations latency
3. Check Redis queue sizes

## Implementation Phases

### Phase 1: Development (1-2 days)

- [ ] Create interfaces and structures
- [ ] Implement cleanup service
- [ ] Add methods to storage

### Phase 2: Integration (1 day)

- [ ] Create scheduler
- [ ] Integrate into application
- [ ] Configuration

### Phase 3: Testing (1 day)

- [ ] Unit tests
- [ ] Integration tests
- [ ] Load testing

### Phase 4: Monitoring (0.5 day)

- [ ] Metrics and alerts
- [ ] Documentation
- [ ] Deployment

## Additional Improvements (future)

1. **Distributed locks** - for multiple instances
2. **Prioritization** - cleanup oldest records first
3. **Statistics** - reports on cleaned data amount
4. **Webhook notifications** - for critical cleanup errors

## Risks and Mitigation

1. **High database load**

   - Mitigation: small batches, pauses between operations

2. **Deleting active sessions**

   - Mitigation: additional expires_at verification

3. **Failure during cleanup**

   - Mitigation: transactions, retry logic

4. **Blocking main operations**
   - Mitigation: separate connection pools for cleanup
