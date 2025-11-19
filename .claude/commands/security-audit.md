# Security Audit Command

Perform a comprehensive security review of the SSO codebase to identify and fix vulnerabilities.

## Security Audit Checklist

### Dependencies

- [ ] Run `go mod tidy` to clean up dependencies
- [ ] Check for vulnerabilities with `govulncheck`
- [ ] Review indirect dependencies for known issues
- [ ] Ensure all dependencies are from trusted sources
- [ ] Verify dependency versions are pinned (no floating versions)

### Secrets & Credentials

- [ ] No hardcoded passwords, API keys, or tokens in code
- [ ] No secrets in environment variable defaults
- [ ] Sensitive data not logged or exposed in errors
- [ ] Secrets managed via environment variables or secret management service
- [ ] Database credentials not in code or version control
- [ ] `.env` files are in `.gitignore`
- [ ] No credentials in configuration files committed to git

### Input Validation

- [ ] All user input is validated and sanitized
- [ ] SQL injection prevented (using parameterized queries, sqlc)
- [ ] Command injection prevented (avoid `os/exec` with user input)
- [ ] Path traversal prevented (validate and sanitize file paths)
- [ ] XXE attacks prevented (secure XML parsing if applicable)
- [ ] Request size limits implemented
- [ ] Rate limiting on sensitive endpoints (login, registration, password reset)
- [ ] gRPC request validation at controller layer

### Authentication

- [ ] Passwords hashed with Argon2 or bcrypt (cost factor ≥ 12)
- [ ] No plain text password storage anywhere
- [ ] JWT tokens properly validated (signature, expiration, claims)
- [ ] Session tokens are cryptographically random (crypto/rand)
- [ ] Token expiration implemented and enforced
- [ ] Secure password reset flow (time-limited tokens)
- [ ] Refresh token rotation on use
- [ ] Token revocation mechanism in place

### Authorization

- [ ] Access control checks on all protected endpoints
- [ ] Users can only access their own resources
- [ ] Role-based access control (RBAC) implemented correctly (if applicable)
- [ ] No privilege escalation vulnerabilities
- [ ] API endpoints require proper authentication
- [ ] Tenant isolation enforced at database query level
- [ ] Authorization checked before any mutation operations

### Data Protection

- [ ] Sensitive data encrypted at rest (if required)
- [ ] TLS/HTTPS enforced for data in transit
- [ ] No sensitive data in logs (passwords, tokens, PII, secrets)
- [ ] PII handling complies with regulations (GDPR, etc.)
- [ ] Secure random number generation (crypto/rand, not math/rand)
- [ ] Session data properly encrypted in Redis
- [ ] Password reset tokens are time-limited and single-use

### API Security

- [ ] CORS configured correctly (not using wildcard `*` in production)
- [ ] Content-Type validation
- [ ] CSRF protection for state-changing operations (if applicable)
- [ ] No verbose error messages exposing internals to clients
- [ ] Security headers set appropriately
- [ ] gRPC error codes don't leak sensitive information
- [ ] Input size limits prevent DoS attacks

### Multi-Tenancy Security

- [ ] Tenant isolation enforced in every database query
- [ ] `tenant_id` or `client_id` included in all relevant tables
- [ ] Cross-tenant data leakage prevented
- [ ] Tenant access rights verified before operations
- [ ] Never trust client-provided tenant identifiers alone
- [ ] Integration tests verify tenant isolation
- [ ] Tenant boundaries tested thoroughly

### Infrastructure

- [ ] Environment variables used for all configuration
- [ ] No debug/development features enabled in production
- [ ] Database connections use least privilege principle
- [ ] File permissions properly restricted
- [ ] Timeouts set for HTTP clients and servers
- [ ] Connection pools configured with appropriate limits
- [ ] Graceful shutdown implemented

### Cryptography

- [ ] Use Go's `crypto` package (not custom crypto)
- [ ] No weak algorithms (MD5, SHA1 for security purposes)
- [ ] Proper random generation with `crypto/rand`
- [ ] TLS minimum version set to 1.2 or higher
- [ ] JWT signing uses RS256 (RSA) algorithm
- [ ] JWKS key rotation implemented
- [ ] Private keys stored securely (S3 with encryption or secure file system)

### Logging & Monitoring

- [ ] Security-relevant events logged (failed auth, access violations)
- [ ] Audit trails for sensitive operations
- [ ] No sensitive data in logs (passwords, tokens, PII)
- [ ] Structured logging with appropriate levels
- [ ] Log retention policy defined
- [ ] Monitoring and alerting for suspicious patterns

### Code Quality

- [ ] No ignored errors with `_`
- [ ] All errors properly wrapped with context
- [ ] No race conditions (run `go test -race ./...`)
- [ ] No goroutine leaks (channels closed, contexts with timeouts)
- [ ] `defer` used correctly (especially in loops)
- [ ] Zero warnings from `golangci-lint run ./...`

### gRPC Security

- [ ] gRPC interceptors for authentication and authorization
- [ ] Proper validation of metadata (client_id, authorization headers)
- [ ] gRPC error codes don't expose sensitive information
- [ ] Request IDs for tracing and audit
- [ ] TLS configured for gRPC communication (production)

### Testing

- [ ] Security-focused unit tests
- [ ] Integration tests for authentication flows
- [ ] Tests for authorization and access control
- [ ] Tests for tenant isolation
- [ ] Fuzzing tests for input validation (if applicable)
- [ ] Penetration testing results reviewed

## Running Security Tools

```bash
# Check for known vulnerabilities in dependencies
govulncheck ./...

# Run linter with security checks
golangci-lint run --enable=gosec,exportloopref ./...

# Run tests with race detector
go test -race ./...

# Check for hardcoded credentials
git grep -i "password\s*=\s*\"" || echo "No hardcoded passwords found"
git grep -i "secret\s*=\s*\"" || echo "No hardcoded secrets found"
git grep -i "api_key\s*=\s*\"" || echo "No hardcoded API keys found"
```

## Common Vulnerabilities to Check

### SQL Injection
- Verify all database queries use parameterized statements
- Check sqlc-generated code is used exclusively for PostgreSQL
- Review MongoDB queries for injection risks

### Authentication Bypass
- Verify JWT validation is comprehensive
- Check token expiration is enforced
- Ensure refresh token rotation

### Authorization Bypass
- Verify tenant isolation in all queries
- Check user can only access their own data
- Ensure RBAC is enforced consistently

### Information Disclosure
- Review error messages returned to clients
- Check logs don't contain sensitive data
- Verify stack traces aren't exposed

### Session Management
- Verify session tokens are cryptographically random
- Check session expiration is enforced
- Ensure sessions are invalidated on logout

## Reporting

After completing the audit, document:

1. **Vulnerabilities Found**: List all security issues discovered
2. **Severity**: Rate each issue (Critical, High, Medium, Low)
3. **Remediation**: Describe how each issue was fixed or should be fixed
4. **Tests Added**: Note any new security tests added
5. **Follow-up**: List any remaining items that need attention

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Best Practices](https://github.com/OWASP/Go-SCP)
- [Uber Go Style Guide](https://github.com/uber-go/guide)
- SSO Project: `.claude/PROJECT_CONTEXT.md` (Security Requirements section)
