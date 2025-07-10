# SSO Commands Cheat Sheet

Quick reference for common development and testing tasks.

## 🚀 Development Commands

### Start Everything

```bash
# Start full stack (SSO + databases + observability)
docker-compose up -d

# Start only infrastructure (no SSO app)
docker-compose up -d postgres redis mongo minio loki prometheus tempo otel-collector grafana

# Start SSO app only (if infrastructure is running)
docker-compose up -d sso
```

### Rebuild & Restart

```bash
# Rebuild SSO and restart
docker-compose up -d --build sso

# Force full rebuild (no cache)
docker-compose build --no-cache sso && docker-compose up -d sso
```

### Status & Logs

```bash
# Check all service status
docker-compose ps

# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f sso
docker-compose logs -f otel-collector
docker-compose logs -f postgres
```

### Stop & Cleanup

```bash
# Stop all services (keep data)
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v

# Stop specific services
docker-compose stop sso postgres redis
```

## 🧪 Testing Commands

### Setup Test Environment

```bash
# 1. Start infrastructure for tests (no SSO app)
docker-compose up -d postgres redis mongo minio otel-collector loki prometheus

# 2. Wait for services to be ready
docker-compose ps

# 3. Set test config
export CONFIG_PATH=./config/config.test.yaml
```

### Run Tests

```bash
# Method 1: Using Makefile (recommended)
make test-docker-full        # Full cycle: setup + test + cleanup
make test-docker-api         # API tests against Docker (requires setup)
make test-docker-unit        # Unit tests (no Docker needed)

# Method 2: Manual steps
docker-compose up -d postgres redis mongo minio otel-collector
export CONFIG_PATH=./config/config.test.yaml
go test ./api_tests/... -v
go test ./internal/... -v

# Method 3: Individual commands
make test-docker-setup       # Start Docker infrastructure
make test-docker-api         # Run API tests
make test-docker-cleanup     # Stop Docker infrastructure
make test-docker-status      # Check Docker status

# Local tests (without Docker)
make test-all-app           # Full local setup + tests
make test-api               # Local API tests only

# Run specific test
go test ./api_tests/login_test.go -v

# Run tests with short flag (skip slow tests)
go test ./internal/... -v -short
```

### Test Cleanup

```bash
# Stop test infrastructure
docker-compose stop

# Full cleanup
docker-compose down -v
```

## 🔧 Database Commands

### Migrations

```bash
# Run migrations
docker-compose exec sso ./migrate up

# Rollback migrations
docker-compose exec sso ./migrate down 1

# Check migration status
docker-compose exec sso ./migrate version
```

### Database Access

```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U sso_user -d sso_db

# Connect to MongoDB
docker-compose exec mongo mongosh sso_dev

# Connect to Redis
docker-compose exec redis redis-cli
```

### Client Registration

```bash
# Register test client
docker-compose exec sso ./register_client \
  --client-id="test-app" \
  --client-secret="secret123" \
  --redirect-uri="http://localhost:3000/callback"
```

## 📊 Observability Commands

### Quick Health Checks

```bash
# Test all telemetry endpoints
curl http://localhost:9090/-/healthy  # Prometheus
curl http://localhost:3100/ready      # Loki
curl http://localhost:3200/ready      # Tempo
curl http://localhost:9080/ready      # Promtail

# Check OTEL Collector health
curl http://localhost:13133/         # Health endpoint
```

### Access Dashboards

```bash
# Open Grafana (admin/admin)
open http://localhost:3000

# Open Prometheus
open http://localhost:9090

# Open MinIO Console (minio_user/minio_password)
open http://localhost:9001
```

### Query Examples

```bash
# Query SSO logs via Loki API
curl -G "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={service="sso"}' \
  --data-urlencode 'limit=5'

# Query Prometheus metrics
curl "http://localhost:9090/api/v1/query?query=up"
```

### Debug Telemetry

```bash
# Check if OTEL Collector is receiving data
docker-compose logs otel-collector | grep "Everything is ready"

# Check SSO telemetry output
docker-compose logs sso | grep -i otel

# Check specific pipeline (logs/metrics/traces)
docker-compose logs otel-collector | grep -E "(loki|prometheus|tempo)"
```

## 🔍 Troubleshooting Commands

### System Resources

```bash
# Check Docker resources
docker system df
docker system prune  # Clean up if needed

# Check container resource usage
docker stats

# Check available memory
free -h  # Linux
vm_stat | head -5  # macOS
```

### Network Connectivity

```bash
# Test from inside containers
docker-compose exec sso ping postgres
docker-compose exec sso ping redis
docker-compose exec sso ping otel-collector

# Test from host to Docker services (for tests)
curl localhost:5432     # PostgreSQL (should connect)
redis-cli -h localhost ping  # Redis (should return PONG)
```

### Log Analysis

```bash
# Find errors in SSO logs
docker-compose logs sso | grep -i error

# Check database connections
docker-compose logs sso | grep -i "connect\|connection"

# Check S3/MinIO operations
docker-compose logs sso | grep -i s3
```

### Reset Everything

```bash
# Nuclear option: full cleanup and restart
docker-compose down -v
docker system prune -f
docker-compose up -d
```

## 💡 Common Workflows

### Development Session

```bash
# 1. Start infrastructure
docker-compose up -d postgres redis mongo minio otel-collector loki prometheus tempo grafana

# 2. Start SSO app
docker-compose up -d sso

# 3. Open Grafana for monitoring
open http://localhost:3000

# 4. Make code changes, then rebuild
docker-compose up -d --build sso
```

### Testing Session

```bash
# Method 1: One command (recommended)
make test-docker-full

# Method 2: Step by step
make test-docker-setup       # Start infrastructure
make test-docker-api         # Run API tests
make test-docker-cleanup     # Stop infrastructure

# Method 3: Manual control
docker-compose up -d postgres redis mongo minio otel-collector
export CONFIG_PATH=./config/config.test.yaml
go test ./api_tests/... -v
docker-compose down

# Method 4: Local tests (no Docker)
make test-all-app           # Full local setup + tests
```

### Debug Session

```bash
# 1. Start with logs in foreground
docker-compose up

# 2. In another terminal, check specific issues
docker-compose logs sso | grep -i error
docker-compose exec sso ping postgres

# 3. Reset problematic service
docker-compose restart sso
```

---

💡 **Tip**: Bookmark this file for quick access to commands during development!

📖 **Full Documentation**: See [README.md](./README.md) for complete setup and architecture details.
