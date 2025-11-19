# SSO Project Context

This document provides essential context about the SSO project architecture, coding standards, and development workflows for Claude Code agents.

## Application Overview

A comprehensive authentication and identity management solution built with Go and modern observability stack, designed for multi-tenancy environments (comparable to Okta/Auth0).

### Core Features

**Authentication**:
- User registration and login
- Password management (reset, change)
- JWT-based authentication with RS256 signing
- Session management with Redis
- User search with cursor-based pagination

**Multi-tenancy**:
- Client application management
- Tenant isolation at database query level

**Planned Features** (not yet implemented):
- Magic link login (SMS/email)
- Passkey support
- OTP login using TOTP authentication
- Role-based access control (RBAC)

### Authentication Flows

- **Built-in login app**: Redirect-based flow with SPA hosted application
- **API-based**: Direct HTTP requests or SDK integration with client applications

---

## Technology Stack

### Core Technologies
- **Go 1.25**: Strictly following Uber Go Style Guide
- **gRPC**: For all service APIs with Protocol Buffers (github.com/rshelekhov/sso-protos)
- **PostgreSQL**: Primary database with sqlc for type-safe queries
- **MongoDB**: Alternative database for flexible document storage
- **Redis**: Session management and caching
- **AWS S3**: Object storage for PEM keys (JWKS key rotation) - MinIO used for local testing
- **Mailgun**: Email service (with mock option for testing)

### Development & Build Tools
- **golang-migrate**: Database migrations
- **sqlc**: Type-safe SQL code generation
- **viper**: Configuration management
- **log/slog**: Structured logging
- **ksuid**: Unique identifiers
- **golangci-lint**: Code linting (zero warnings policy)
- **testify**: Testing framework (assert, require, mock, suite)
- **mockery**: Mock generation for interfaces

### Observability Stack
- **OpenTelemetry Collector**: Telemetry data router and processor
- **Prometheus**: Metrics collection and storage
- **Grafana**: Unified observability dashboard
- **Loki**: Log aggregation and search
- **Tempo**: Distributed tracing
- **Promtail**: Log collection agent

### Security & Authentication
- **Argon2**: Password hashing algorithm
- **JWT**: Token-based authentication
- **JWKS**: JSON Web Key Set for key rotation
- **RS256**: RSA signature algorithm

---

## Clean Architecture Structure

The application follows clean architecture principles with clear layer separation:

```
/cmd
  /migrate              - Database migration CLI tool
  /register_client      - Client registration CLI tool
  /sso                  - Main application entry point

/internal/app           - Application setup and server management (gRPC + HTTP)

/internal/config        - Configuration management and initialization

/internal/controller/grpc - gRPC handlers and transport layer
  - Handles request/response mapping
  - Input validation
  - Delegates to use cases
  - Returns appropriate gRPC status codes

/internal/domain
  /entity               - Domain models and business objects (no external dependencies)
  /service              - Core business logic services:
    /clientvalidator    - Validates clients by clientID, manages permissions
    /session            - Session lifecycle management (creation, refresh, deletion, validation)
    /token              - JWT management (creation, validation, revocation)
    /userdata           - User data management (CRUD, profile management)
    /verification       - Verification token management (registration/password confirmation)

  /usecase              - Application use cases implementing business logic:
    /auth               - Authentication and authorization (register, login, logout, token refresh)
    /client             - Client management (registration, validation, configuration)
    /user               - User management (profile updates, user deletion, search)

/internal/infrastructure
  /service
    /mail               - Email service implementations:
      /mailgun          - Mailgun integration
      /mocks            - Mock email service for testing

  /storage              - Database connections and repository implementations:
    /auth               - Authentication storage
      /mongo            - MongoDB implementation
      /postgres         - PostgreSQL implementation with sqlc
    /client             - Client management storage
      /mongo            - MongoDB implementation
      /postgres         - PostgreSQL implementation with sqlc
    /device             - Device management storage
      /mongo            - MongoDB implementation
      /postgres         - PostgreSQL implementation with sqlc
    /key                - PEM key storage
      /fs               - File system implementation
      /s3               - AWS S3 implementation (MinIO used only for local testing)
    /mongo/common       - Shared MongoDB utilities and collections
    /session            - Session storage
      /redis            - Redis implementation
    /transaction        - Transaction management interfaces and implementations
    /user               - User management storage
      /mongo            - MongoDB implementation
      /postgres         - PostgreSQL implementation with sqlc
    /verification       - Verification token storage
      /mongo            - MongoDB implementation
      /postgres         - PostgreSQL implementation with sqlc

/internal/lib
  /cursor               - Cursor-based pagination utilities
  /e                    - Error handling and logging helpers
  /interceptor          - gRPC interceptors:
    /auth               - Authentication and authorization
    /clientid           - Client ID extraction and validation
    /metrics            - Metrics collection
  /logger               - Structured logging implementation:
    /slogdiscard        - Null logger for unit tests

/internal/observability
  /metrics              - Prometheus metrics definitions and helpers
  /tracing              - OpenTelemetry tracing setup

/pkg                    - Reusable packages:
  /grpcerrors           - gRPC error handling utilities
  /jwtauth              - JWT authentication utilities

/migrations             - PostgreSQL database migrations (golang-migrate format)

/api_tests              - Integration tests using real HTTP/gRPC requests

/static/email_templates - HTML email templates for user communications

github.com/rshelekhov/sso-protos - External: Protocol Buffer definitions
```

### Layer Responsibilities

**Domain Layer** (`/internal/domain`):
- Pure business logic
- No infrastructure dependencies
- Defines interfaces that infrastructure implements
- Domain entities, services, and use cases

**Infrastructure Layer** (`/internal/infrastructure`):
- Implements interfaces defined by domain
- Database access (PostgreSQL, MongoDB, Redis)
- External service integrations (email, S3)
- Transaction management

**Controller Layer** (`/internal/controller`):
- Handles transport concerns (gRPC)
- Request validation and sanitization
- Response mapping
- Delegates to use cases
- Error handling and status code mapping

**Config Layer** (`/internal/config`):
- Centralized configuration management
- Environment-specific settings
- Viper-based configuration loading

**Observability Layer** (`/internal/observability`):
- Metrics definitions and recording
- Tracing setup and span management
- Integration with OpenTelemetry

---

## Go Coding Guidelines

### Basic Principles

- Use English for all code and documentation
- Always specify types explicitly for variables and function signatures
- Avoid using `interface{}` unless absolutely necessary
- Define appropriate structs and interfaces
- Use GoDoc comments for all exported functions, methods, and types
- Maintain consistent formatting with `gofmt` and `goimports`
- One primary export per file where possible
- Follow Uber Go Style Guide: https://github.com/uber-go/guide

### Nomenclature

- **PascalCase**: Exported functions, types, and structs
- **camelCase**: Unexported variables, functions, and methods
- **kebab-case**: File and directory names
- **UPPERCASE**: Environment variables and constants
- **Prefix boolean variables** with verbs: `is`, `has`, `can`, `should`
- Use full words instead of abbreviations (except standard ones: `API`, `URL`, `HTTP`, `JWT`)
- Common abbreviations:
  - `ctx` for context.Context
  - `req`, `resp` for request and response
  - `err` for errors
  - `db` for database connections
  - `tx` for transactions

### Functions

- Keep functions short and focused (ideally < 20 lines, max 100 lines)
- Name functions with a verb and an object: `CreateUser`, `ValidateToken`, `FetchUserByID`
- Boolean-returning functions: `IsValid`, `HasPermission`, `CanAccess`
- Procedures: `ExecuteQuery`, `SaveUser`, `ProcessRequest`
- Reduce nested blocks by using early returns
- Use helper functions to reduce complexity
- Maintain a single level of abstraction per function
- Reduce parameter count (max 3-4 parameters, use structs for more)

### Data

- Avoid excessive use of primitive types; encapsulate data in structs
- Use immutability where possible
- Use `const` for unchanging literals
- Use pointers when mutability is required or for large structs
- Validate inputs at boundaries (controller/handler level)

### Structs and Interfaces

- Follow SOLID principles
- Favor composition over inheritance
- Use interfaces to define contracts: "Accept interfaces, return structs"
- Keep interfaces small and focused (Interface Segregation Principle)
- Keep structs small and focused (fewer than 10 fields where possible)
- Use method receivers (`func (s *Struct) Method()`) when mutation is required

### Error Handling

**Critical Principles**:
- Use Go's error handling idioms (`if err != nil`)
- Always return errors, never panic (except truly unrecoverable init scenarios)
- Wrap errors with context: `fmt.Errorf("failed to create user: %w", err)`
- Define custom error types in `errors.go` within each package
- Log errors only at boundaries (handler/controller level)
- Return appropriate gRPC status codes to clients
- Never expose internal error details to external APIs
- Test error paths explicitly

**Error Wrapping Pattern**:
```go
if err := someOperation(); err != nil {
    return fmt.Errorf("operation context: %w", err)
}
```

### Context Management

- Use `context.Context` for all I/O operations (database, Redis, external calls)
- Pass context as the **first parameter** in functions
- Respect context cancellation and timeouts
- Propagate context through call chains
- Use `context.WithTimeout` for operations with time limits

### Resource Management

- Use `defer` for cleanup (file close, connection release, mutex unlock)
- Be careful with `defer` in loops (may cause resource leaks)
- No goroutine leaks - always have termination conditions
- Use connection pooling for database and Redis
- Close resources explicitly

### Input Validation

- Validate all inputs at controller/handler layer
- Sanitize user input to prevent injection attacks
- Use strong typing to enforce constraints
- Return meaningful validation errors to clients
- Never trust client-provided data

### Logging

- Use structured logging (log/slog)
- Log at appropriate levels: debug, info, warn, error
- **NEVER log sensitive data**: passwords, tokens, PII, secrets, API keys
- Include relevant context: user_id, tenant_id, request_id, client_id
- Log errors with full context at boundaries
- Use consistent field names across the application

**Sensitive Data - Never Log**:
- Passwords (plain text or hashed)
- Authentication tokens (JWT, refresh tokens, session tokens)
- API keys and secrets
- PII (Personally Identifiable Information)
- Credit card numbers
- Social security numbers
- Any user credentials

### Constants and Enums

- Use constants for magic numbers and strings
- Group related constants in blocks
- Use `iota` for enumeration types
- Define constants at package level or in dedicated `constants.go`

### Testing

**Test Organization**:
- Place tests in the same directory as the code they test
- Use `testing` package for unit tests
- Follow Arrange-Act-Assert (AAA) pattern
- Use table-driven tests where applicable
- Use `testify/require` for critical assertions (test cannot continue if fails)
- Use `testify/assert` for non-critical assertions
- Use `testify/suite` for integration tests requiring setup/teardown
- Use `testify/mock` or `mockery` for mocking dependencies
- Use descriptive test names: `TestFunctionName_Scenario_ExpectedResult`

**Test File Structure**:
1. Test setup/fixtures
2. Helper functions
3. Test table definitions
4. Actual test functions

**Test Coverage**:
- Aim for >80% test coverage for new code
- Test happy paths
- Test error paths
- Test edge cases
- Test concurrent access where relevant

**Mock Generation**:
- Use `mockery` for generating mocks from interfaces
- Mocks are stored in `mocks/` subdirectories
- Configure mockery in `.mockery.yaml`

### Documentation

- Every exported function must have a GoDoc comment
- GoDoc comments should start with the element name
- Explain "why" not just "what" in comments
- Include examples for complex functions
- Document expected errors and edge cases
- Keep README.md up to date with:
  - Project overview
  - Setup instructions
  - Configuration options
  - API documentation

### Dependencies

- Keep external dependencies minimal
- Use go modules for dependency management
- Run `go mod tidy` regularly
- Pin important dependencies to specific versions
- Review dependency licenses

---

## Security Requirements

### Data Protection

- **Never hardcode secrets**: Use environment variables
- **Never log sensitive data**: passwords, tokens, API keys, PII
- Use secure random generation: `crypto/rand` not `math/rand`
- Hash passwords with Argon2 or bcrypt (cost factor ≥ 12)
- Encrypt sensitive data at rest when required
- Use TLS for all external communication
- Use mTLS for inter-service communication when possible

### Query Security

- **Prevent SQL injection**: Use parameterized queries (sqlc provides this automatically)
- Validate and sanitize all inputs
- Use prepared statements exclusively
- Never concatenate user input into SQL queries

### Authentication & Authorization

- Validate JWT signatures and claims properly
- Implement token expiration and refresh logic
- Apply principle of least privilege
- Enforce tenant isolation at database query level
- Implement rate limiting for authentication endpoints
- Use secure token storage mechanisms
- Rotate refresh tokens on use
- Implement token revocation mechanisms

### Multi-Tenancy Security

**Critical**: Tenant isolation must be enforced at every layer
- Include `tenant_id` (or `client_id`) in all relevant tables
- Filter by tenant in every database query
- Never trust client-provided tenant identifiers alone
- Verify tenant access rights before operations
- Prevent cross-tenant data leakage
- Test tenant boundaries thoroughly in integration tests

### Input Validation

- Validate all user input at controller layer
- Sanitize inputs to prevent injection attacks
- Use strong typing to enforce constraints
- Implement request size limits
- Implement rate limiting on sensitive endpoints

### Security Monitoring

- Flag potential security concerns immediately
- Log security-relevant events: failed auth, access violations, permission denials
- Implement audit trails for sensitive operations
- Monitor for suspicious patterns

---

## Database Practices

### PostgreSQL with sqlc

- Use sqlc-generated code for all PostgreSQL queries
- Write SQL queries in `.sql` files for sqlc generation
- Use prepared statements (sqlc does this automatically)
- Handle NULL values explicitly
- Use transactions for multi-step operations
- Implement proper error handling for constraint violations
- Create indexes for frequently queried columns
- Design for multi-tenancy from day one (tenant_id in relevant tables)

**Migration Management**:
- Use golang-migrate for schema changes
- All migrations must be reversible when possible
- Test migrations in development before applying to production
- Version migrations with sequential numbering
- Store migrations in `/migrations` directory

### Query Optimization

- Create proper indexes for query performance
- Avoid N+1 query problems
- Use pagination for list operations (cursor-based for large datasets)
- Batch operations when possible
- Profile queries to identify bottlenecks

### MongoDB (when applicable)

- Use for flexible schemas that would be painful in PostgreSQL
- Design collections with query patterns in mind
- Include tenant_id in all documents for isolation
- Use appropriate indexes
- Use connection pooling
- Handle schema validation

### Redis

- Use for sessions, caching, and distributed locks
- Set appropriate TTLs
- Use key prefixes for organization (e.g., `session:`, `cache:`)
- Use connection pooling
- Handle network errors gracefully

---

## gRPC API Design

- Define clear, versioned proto files in external repo (sso-protos)
- Use semantic versioning for breaking changes
- Include comprehensive comments in proto definitions
- Design for backward compatibility
- Use proper gRPC error codes
- Implement interceptors for cross-cutting concerns:
  - Authentication and authorization
  - Client ID extraction and validation
  - Request ID tracking
  - Metrics collection
  - Logging

---

## Development Workflow

### Implementing New Features

1. **Define or update domain entities** in `/internal/domain/entity`
2. **Update storage interfaces** in domain use cases
3. **Implement storage layer** in `/internal/infrastructure/storage`
4. **Create database migrations** if schema changes are needed
5. **Implement business logic** in domain services or use cases
6. **Create gRPC controller** handlers in `/internal/controller/grpc`
7. **Add comprehensive tests** at all layers (unit + integration)
8. **Run quality checks**: `golangci-lint`, `go build`, `go test`
9. **Update documentation**: godoc comments, README, API docs

### Before Committing

- [ ] Code builds successfully: `go build ./...`
- [ ] All tests pass: `go test ./...`
- [ ] Linter shows zero warnings: `golangci-lint run ./...`
- [ ] No race conditions: `go test -race ./...`
- [ ] Godoc comments for all exported elements
- [ ] No hardcoded secrets or sensitive data
- [ ] No sensitive data in logs
- [ ] Tenant isolation enforced (if applicable)

---

## Commit Message Format

Follow conventional commits with the 50/72 rule:

### Structure
```
<type>: <subject>

<body>

<footer>
```

### Subject Line Rules
- **Length**: Maximum 50 characters
- **Format**: `<type>: <subject>`
- **Capitalization**: First letter of subject must be capitalized
- **Mood**: Use imperative mood ("Add feature" not "Added feature")
- **Punctuation**: No period at the end

### Types
- `feat` - New feature
- `fix` - Bug fix
- `refactor` - Code refactoring (no functional changes)
- `perf` - Performance improvements
- `test` - Adding or updating tests
- `docs` - Documentation changes
- `chore` - Maintenance tasks (dependencies, configs, build)
- `style` - Code style changes (formatting, no logic changes)

### Body (Optional but Recommended)
- **Line Length**: Maximum 72 characters per line
- **Content**: Explain **what** and **why**, not **how**
- **Separation**: Leave one blank line between subject and body

### Footer (Optional)
- **Issue References**: `Fixes #123`, `Closes #456`, `Relates to #789`
- **Breaking Changes**: Use `BREAKING CHANGE:` prefix

### Examples

**Simple commit**:
```
feat: Add user search endpoint with cursor pagination
```

**Commit with body**:
```
fix: Prevent race condition in session cleanup

The session cleanup goroutine could access sessions while being
modified by the main handler. Added proper mutex locks to ensure
thread-safe access to the session map.

Fixes #234
```

**Breaking change**:
```
feat: Change password hash algorithm to Argon2

Migrated from bcrypt to Argon2id for password hashing to improve
security against modern attack vectors.

BREAKING CHANGE: Existing password hashes will need to be
re-hashed on next user login. Migration script provided in
scripts/migrate-passwords.sh
```

---

## Best Practices Summary

1. **Simplicity First**: Write obvious, maintainable code over clever solutions
2. **Security by Design**: Every line of code must consider security implications
3. **Clean Architecture**: Respect layer boundaries and dependency rules
4. **Go Idioms**: Follow Go conventions and Uber Style Guide
5. **Test Coverage**: Aim for >80% coverage with meaningful tests
6. **Zero Warnings**: golangci-lint must show zero warnings
7. **Tenant Isolation**: Enforce multi-tenancy at every layer
8. **Error Handling**: Always wrap errors with context, never ignore them
9. **Context Propagation**: Use context.Context for all I/O operations
10. **Documentation**: Every exported element must have godoc comments

---

## Configuration Files

- **`config/config.docker.yaml`**: Docker Compose deployment (internal service names)
- **`config/config.test.yaml`**: Running tests locally against Docker services (localhost)
- **`config/config.example.yaml`**: Template for local development

Key differences:
- Docker: `OTLPEndpoint: "otel-collector:4317"`, `postgres:5432`
- Test/Local: `OTLPEndpoint: "localhost:4317"`, `localhost:5432`

---

## Quick Reference

### Running the Application
```bash
# Docker Compose (recommended)
docker compose up -d

# Local development
export CONFIG_PATH=./config/config.yaml
make run-server
```

### Testing
```bash
# Unit tests
go test ./internal/... -v

# Integration tests
export CONFIG_PATH=./config/config.test.yaml
go test ./api_tests/... -v

# All tests with race detector
go test -race ./...
```

### Code Quality
```bash
# Linting
golangci-lint run ./...

# Build verification
go build ./...

# Generate mocks
mockery
```

### Database
```bash
# Run migrations
make migrate

# Register client
./register_client --client-id="app" --client-secret="secret"
```

---

**Last Updated**: 2025-11-08

**Maintainers**: Development Team

**Note**: This document should be referenced by all Claude Code agents working on the SSO project to maintain consistency and quality.
