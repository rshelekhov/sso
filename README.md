# SSO Service (gRPC + HTTP/REST)

A comprehensive authentication and identity management solution built with Go, offering both gRPC and HTTP/REST APIs with a modern observability stack.

## Overview

This SSO (Single Sign-On) service combines authentication and user information management in a single, production-ready application. It provides **dual API access** (gRPC for high performance and HTTP/REST for easy integration), complete observability, and full multi-tenancy support.

**Key Capabilities:**

- **Dual API**: Both gRPC (port 44044) and HTTP/REST (port 8080) running simultaneously
- **Authentication**: User registration, email verification, login, password management
- **Multi-tenancy**: Support for multiple client applications with JWT-based auth
- **Observability**: Comprehensive metrics, logs, and distributed tracing
- **Production-ready**: Docker Compose setup with all dependencies
- **SDK-friendly**: HTTP API designed for TypeScript/JavaScript SDK development

## Getting Started

### Prerequisites

- **Docker** and **Docker Compose** (recommended)
- **Go 1.21+** (for local development)

### Quick Start

The fastest way to get everything running:

```bash
# Clone the repository
git clone https://github.com/rshelekhov/sso.git
cd sso

# Start the complete stack (SSO + databases + observability)
docker compose up -d

# Check service status
docker compose ps

# Access Grafana dashboard
open http://localhost:3000  # admin/admin
```

### Alternative: Local Development

For Go development without Docker:

1. **Setup dependencies**: PostgreSQL, Redis, MinIO
2. **Copy config**: `cp config/config.example.yaml config/config.yaml`
3. **Set environment**: `export CONFIG_PATH=./config/config.yaml`
4. **Run migrations**: `make migrate` (if you use postgres you need to install [golang-migrate](https://github.com/golang-migrate/migrate) tool for running database migrations for postgres. And you need to have `psql` (PostgreSQL interactive terminal), because this tool is used in the commands described in the makefile.)
5. **Start server**: `make run-server`

## API Access

The SSO service provides **both gRPC and HTTP/REST APIs** running simultaneously:

- **gRPC Server**: `localhost:44044` - High-performance gRPC API
- **HTTP/REST Gateway**: `localhost:8080` - RESTful HTTP API (via grpc-gateway)

### HTTP/REST API Examples

Quick test of the HTTP API:

```bash
# Health check (Get JWKS - public endpoint)
curl http://localhost:8080/v1/auth/.well-known/jwks.json

# Register a new user
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "confirm_password": "SecurePassword123!",
    "name": "John Doe"
  }'

# Login
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "user_device_data": {
      "user_agent": "curl/8.0",
      "ip": "127.0.0.1",
      "platform": "PLATFORM_WEB"
    }
  }'
```

### Available Endpoints

**Authentication** (`/v1/auth/*`):
- `POST /v1/auth/register` - Register new user
- `POST /v1/auth/verify-email` - Verify email address
- `POST /v1/auth/login` - User login
- `POST /v1/auth/refresh` - Refresh access token
- `POST /v1/auth/logout` - User logout
- `POST /v1/auth/reset-password` - Request password reset
- `POST /v1/auth/change-password` - Change password
- `GET /v1/auth/.well-known/jwks.json` - Get JWKS for token verification

**User Management** (`/v1/user/*`):
- `GET /v1/user` - Get current user profile
- `GET /v1/user/{user_id}` - Get user by ID (admin)
- `PATCH /v1/user` - Update current user
- `DELETE /v1/user` - Delete current user
- `DELETE /v1/user/{user_id}` - Delete user by ID (admin)
- `GET /v1/users/search` - Search users

**Client Management** (`/v1/clients/*`):
- `POST /v1/clients/register` - Register new client application

### Documentation & Examples

- **Complete HTTP API Documentation**: See [`docs/HTTP_API_EXAMPLES.md`](docs/HTTP_API_EXAMPLES.md)
- **TypeScript/Bun Examples**: See [`examples/http/`](examples/http/)
  - Authentication flow
  - Token refresh
  - Error handling
  - User management

### Building a TypeScript SDK

If you're building a TypeScript SDK for this service:

1. Check [`SDK_BEST_PRACTICES.md`](SDK_BEST_PRACTICES.md) for comprehensive SDK development guidelines
2. Use the TypeScript examples in `examples/http/` as reference implementations
3. The HTTP API works with Bun, Node.js 18+, Deno, and browsers

## Testing

### Integration Tests

Tests run against Docker Compose services:

```bash
# Start test infrastructure
docker compose up -d postgres redis mongo minio otel-collector

# Set test configuration
export CONFIG_PATH=./config/config.test.yaml

# Run API tests
go test ./api_tests/... -v

# Cleanup
docker compose down
```

### Unit Tests

```bash
# Run all unit tests
go test ./internal/... -v

# Run with coverage
go test ./internal/... -v -cover

# Run linters
make lint
```

## Built With

### Core Technologies

- **PostgreSQL** - Main database
- **MongoDB** - Alternative database option
- **Redis** - Session and cache storage
- **MinIO** - S3-compatible object storage for PEM keys
- **Mailgun** - Email service (with mock option)

### Development & Build Tools

- [golang-migrate](https://github.com/golang-migrate/migrate) - Database migrations
- [sqlc](https://github.com/sqlc-dev/sqlc) - Type-safe SQL code generation
- [viper](https://github.com/spf13/viper) - Configuration management
- [log/slog](https://pkg.go.dev/log/slog) - Structured logging
- [ksuid](https://github.com/segmentio/ksuid) - Unique identifiers
- [golangci-lint](https://github.com/golangci/golangci-lint) - Code linting

### Observability Stack

- **OpenTelemetry Collector** - Telemetry data router and processor
- **Prometheus** - Metrics collection and storage
- **Grafana** - Unified observability dashboard
- **Loki** - Log aggregation and search
- **Tempo** - Distributed tracing
- **Promtail** - Log collection agent

### Security & Authentication

- **Argon2** - Password hashing algorithm
- **JWT** - Token-based authentication
- **JWKS** - JSON Web Key Set for key rotation
- **RS256** - RSA signature algorithm

## Features

### Core Authentication Features

- User login and registration
- Password management (reset, change)
- Multiple authentication methods:
  - Password-based login
  - Magic link login (SMS/email) (not implemented yet)
  - Passkey support (not implemented yet)
  - OTP login using TOTP authentication (not implemented yet)
- User profile management

### Multi-tenancy Support

- Create and manage multiple applications
- Role-based access control (not implemented yet)

### Authentication Flows

- Built-in login app: Redirect-based flow with SPA hosted application
- API-based: Direct HTTP requests or SDK integration with client applications

## Quick Start with Docker Compose

For the complete setup including observability stack, see the **[Quick Start Commands](#quick-start-commands)** section below.

**TL;DR:**

```bash
# Start everything
docker compose up -d

# Run tests
export CONFIG_PATH=./config/config.test.yaml
go test ./api_tests/... -v

# Access Grafana
open http://localhost:3000  # admin/admin
```

**Quick Commands**: See [COMMANDS.md](./COMMANDS.md) for a complete cheat sheet.

### Verifying S3 (MinIO) Integration

1. **Check MinIO initialization:**

   ```bash
   docker compose logs minio-init
   ```

2. **Verify bucket creation:**

   ```bash
   # Access MinIO console at localhost:9001
   # Login: minio_user / minio_password
   # Check if 'sso-keys' bucket exists
   ```

3. **Test S3 connectivity from SSO:**
   ```bash
   # Check SSO logs for S3 operations
   docker compose logs sso | grep -i s3
   ```

### Verifying Logging Stack

1. **Check Promtail is collecting logs:**

   ```bash
   # Promtail should be healthy
   docker compose ps promtail

   # Check Promtail logs
   docker compose logs promtail
   ```

2. **Verify Loki is receiving logs:**

   ```bash
   # Query Loki directly (range query - last 30 minutes)
   START=$(date -v-30M +%s)000000000
   curl -G -s "http://localhost:3100/loki/api/v1/query_range" \
     --data-urlencode 'query={job="docker"}' \
     --data-urlencode "start=${START}" \
     --data-urlencode 'limit=10' | jq '.data.result | length'

   # Check specific service logs
   curl -G -s "http://localhost:3100/loki/api/v1/query_range" \
     --data-urlencode 'query={service="sso"}' \
     --data-urlencode "start=${START}" \
     --data-urlencode 'limit=5' | jq '.data.result[0].values[0][1]' 2>/dev/null || echo "No SSO logs yet"
   ```

3. **Access logs in Grafana:**
   - Go to `localhost:3000`
   - Login: admin/admin
   - Navigate to Explore
   - Select Loki datasource
   - Query: `{service="sso"}` or `{service="postgres"}`

### Troubleshooting

#### S3/MinIO Issues

```bash
# Check MinIO health
curl http://localhost:9000/minio/health/ready

# Check bucket exists
docker exec -it sso-minio-1 mc ls local/

# Recreate MinIO initialization
docker compose up -d --force-recreate minio-init
```

#### Logging Issues

```bash
# Check Promtail configuration
docker compose exec promtail cat /etc/promtail/config.yaml

# Check Docker socket access
docker compose exec promtail ls -la /var/run/docker.sock

# Restart logging stack
docker compose restart promtail loki grafana
```

#### Container Logs Not Appearing

```bash
# Check container logging configuration
docker inspect sso-sso-1 | grep -A 10 "LogConfig"

# Check if labels are set
docker inspect sso-sso-1 | grep -A 5 "Labels"
```

## Development Setup

### Local Development

For local development without Docker, see the development section below.

### Database Migrations

```bash
# Run migrations
docker compose exec sso ./migrate up

# Or run migrations tool directly
go run cmd/migrate/main.go up
```

### Client Registration

```bash
# Register a new client
docker compose exec sso ./register_client \
  --client-id="my-app" \
  --client-secret="secret123" \
  --redirect-uri="http://localhost:3000/callback"
```

## Configuration

The application uses YAML configuration files:

- `config/config.docker.yaml` - Docker environment
- `config/config.example.yaml` - Template for local development
- `config/config.test.yaml` - Test environment

### Key Configuration Sections

#### S3/MinIO Storage

```yaml
KeyStorage:
  Type: "s3"
  S3:
    Region: "us-east-1"
    Bucket: "sso-keys"
    AccessKey: "minio_user"
    SecretKey: "minio_password"
    Endpoint: "minio:9000"
```

#### Logging

The application outputs structured JSON logs to stdout, which are collected by Promtail and sent to Loki.

## Architecture

### System Overview

```
SSO Application (gRPC)
  ↓ OTLP (OpenTelemetry Protocol)
OpenTelemetry Collector (Central Hub)
  ├─→ Prometheus (Metrics)
  ├─→ Loki (Logs)
  └─→ Tempo (Traces)
  ↓ ↓ ↓
Grafana (Unified Observability Dashboard)
```

### Telemetry Stack

The application includes a comprehensive observability stack:

**OpenTelemetry Collector**

- Receives telemetry data from SSO app via OTLP (ports 4317/4318)
- Processes, enriches, and routes data to appropriate backends
- Provides correlation between metrics, logs, and traces

**Metrics (Prometheus)**

- Collects application and infrastructure metrics
- SSO app metrics via OTLP → OTEL Collector → Prometheus
- System metrics from exporters (Redis, PostgreSQL, etc.)
- Available at: `http://localhost:9090`

**Logs (Loki)**

- Centralized log aggregation and storage
- SSO structured logs via OTLP → OTEL Collector → Loki
- Container logs via Promtail → Loki
- Available at: `http://localhost:3100`

**Traces (Tempo)**

- Distributed request tracing
- Shows complete request flow through the system
- Generates service graphs and span metrics
- Available at: `http://localhost:3200`

**Grafana**

- Unified observability dashboard
- Connects to all telemetry backends
- Pre-configured datasources for easy exploration
- Available at: `http://localhost:3000` (admin/admin)

### Configuration Files

The application uses different configuration files for different environments:

- **`config/config.docker.yaml`** - For Docker Compose deployment (internal service names)
- **`config/config.test.yaml`** - For running tests locally against Docker services (localhost endpoints)
- **`config/config.example.yaml`** - Template for local development

Key differences:

```yaml
# config.docker.yaml (inside Docker network)
OTLPEndpoint: "otel-collector:4317"
Storage.Postgres.ConnURL: "postgres://...@postgres:5432/..."

# config.test.yaml (from host to Docker)
OTLPEndpoint: "localhost:4317"
Storage.Postgres.ConnURL: "postgres://...@localhost:5432/..."
```

## Quick Start Commands

### Development & Production

**Start the complete stack:**

```bash
# Start all services (SSO + databases + observability)
docker compose up -d

# Check service health
docker compose ps

# View all logs
docker compose logs -f

# View specific service logs
docker compose logs -f sso
docker compose logs -f otel-collector
```

**Stop and cleanup:**

```bash
# Stop all services
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v
```

### Running Tests

**Prerequisites for testing:**

```bash
# Start infrastructure services (without SSO app)
docker compose up -d postgres redis mongo minio loki prometheus otel-collector

# Wait for services to be ready
docker compose ps
```

**Run tests:**

```bash
# Set test configuration
export CONFIG_PATH=./config/config.test.yaml

# Run API tests (integration tests against running Docker services)
go test ./api_tests/... -v

# Run unit tests
go test ./internal/... -v

# Run all tests
make test-all
```

**Stop test infrastructure:**

```bash
# Stop only infrastructure (keep data)
docker compose stop

# Or full cleanup
docker compose down -v
```

### Development Workflows

**Rebuilding SSO application:**

```bash
# Rebuild and restart SSO service only
docker compose up -d --build sso

# Force rebuild without cache
docker compose build --no-cache sso
docker compose up -d sso
```

**Accessing services:**

- **SSO Application**: `localhost:44044` (gRPC)
- **Grafana**: `localhost:3000` (admin/admin)
- **Prometheus**: `localhost:9090`
- **Loki**: `localhost:3100`
- **MinIO Console**: `localhost:9001` (minio_user/minio_password)

**Database operations:**

```bash
# Run migrations
docker compose exec sso ./migrate up

# Register a client
docker compose exec sso ./register_client \
  --client-id="test-app" \
  --client-secret="secret123" \
  --redirect-uri="http://localhost:3000/callback"

# Connect to PostgreSQL
docker compose exec postgres psql -U sso_user -d sso_db
```

### Observability

**Quick health checks:**

```bash
# Check if telemetry is working
curl http://localhost:9090/api/v1/targets  # Prometheus targets
curl http://localhost:3100/ready           # Loki readiness
curl http://localhost:3200/ready           # Tempo readiness

# Query logs via API
curl -G "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={service="sso"}' \
  --data-urlencode 'limit=5'
```

**Grafana Exploration:**

1. Open `http://localhost:3000` (admin/admin)
2. Go to **Explore**
3. Select datasource:
   - **Loki** for logs: `{service="sso"}`
   - **Prometheus** for metrics: `http_requests_total`
   - **Tempo** for traces: Search by service name

## Troubleshooting

### Common Issues

**Services not starting:**

```bash
# Check Docker resources (need ~4GB RAM)
docker system df
docker system prune  # Clean up if needed

# Check logs for specific issues
docker compose logs otel-collector
docker compose logs sso
```

**No telemetry data:**

```bash
# Verify OTEL Collector is receiving data
docker compose logs otel-collector | grep "Everything is ready"

# Check SSO is sending telemetry
docker compose logs sso | grep -i otel

# Verify configuration
docker compose exec sso cat /app/config.yaml | grep OTLPEndpoint
```

**Database connection issues:**

```bash
# For tests: ensure services are accessible on localhost
curl http://localhost:5432  # Should connect to PostgreSQL
redis-cli -h localhost ping  # Should return PONG

# For Docker: check internal network connectivity
docker compose exec sso ping postgres
```
