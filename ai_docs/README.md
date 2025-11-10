# AI Documentation - SSO Project

This directory contains comprehensive documentation for the SearchUsers feature implementation.

---

## SearchUsers Feature - Complete Documentation

**Status**: ✅ **COMPLETE** - Production Ready

### 📄 Implementation Summary (START HERE)

**File**: `IMPLEMENTATION_SUMMARY_SearchUsers.md`

**Purpose**: Complete historical record of the SearchUsers feature implementation

**Contents**:
- Executive summary of what was built
- Detailed implementation breakdown
- Architecture and design decisions
- Quality assurance results (tests, linter, build status)
- Complete file change list
- Testing instructions (automated + manual)
- Deployment guide
- Issues encountered and resolved
- Prioritized next steps
- Comprehensive metrics

**Size**: 40KB (1,224 lines)

**Use when**:
- Understanding the complete feature
- Team handoff and onboarding
- Deployment planning
- Historical reference
- QA validation
- Troubleshooting

---

## What Was Implemented

**Feature**: SearchUsers gRPC endpoint with cursor-based pagination

**Key Components**:
- [x] gRPC API endpoint (`user.v1.UserService/SearchUsers`)
- [x] Cursor-based pagination for efficient large result sets
- [x] Multi-backend support (PostgreSQL + MongoDB)
- [x] JWT authentication and authorization
- [x] SQL injection prevention and security
- [x] Database indexes for performance
- [x] OpenTelemetry tracing and Prometheus metrics
- [x] Comprehensive testing (100+ test cases)
- [x] Complete documentation

**Code Changes**:
- 54 files changed (47 modified + 7 new)
- +949/-41 lines of code
- 2 database migrations (up + down)
- 1 new cursor pagination package
- 4 new storage methods

**Quality Status**:
- ✅ Build: PASS
- ✅ Tests: ALL PASSING
- ✅ Linter: 0 warnings
- ✅ Race detector: 0 races

---

## Quick Testing Reference

### Prerequisites
1. Get JWT token via Login endpoint
2. Export token: `export JWT_TOKEN="<access_token>"`

### Basic Search
```bash
grpcurl -plaintext -d '{
  "query": "john",
  "page_size": 10
}' \
-H "authorization: Bearer ${JWT_TOKEN}" \
localhost:44044 user.v1.UserService/SearchUsers
```

### Paginated Search
```bash
# Use next_page_token from previous response
grpcurl -plaintext -d '{
  "query": "john",
  "page_size": 10,
  "page_token": "<next_page_token_from_response>"
}' \
-H "authorization: Bearer ${JWT_TOKEN}" \
localhost:44044 user.v1.UserService/SearchUsers
```

### Run All Tests
```bash
# Unit tests
go test ./...

# Integration tests
make test-docker-full

# With race detector
go test -race ./...
```

---

## Key Files in Codebase

### Implementation
- **Controller**: `internal/controller/grpc/user.go` (SearchUsers handler)
- **Usecase**: `internal/domain/usecase/user/user_usecase.go` (business logic)
- **Storage (Postgres)**: `internal/infrastructure/storage/user/postgres/user.go`
- **Storage (Mongo)**: `internal/infrastructure/storage/user/mongo/user.go`
- **SQL Queries**: `internal/infrastructure/storage/user/postgres/query/user.sql`
- **Validation**: `internal/controller/grpc/validation.go`
- **Cursor Logic**: `internal/lib/cursor/cursor.go`

### Database
- **Migration Up**: `migrations/000003_add_search_indexes.up.sql`
- **Migration Down**: `migrations/000003_add_search_indexes.down.sql`
- **Indexes**: `idx_users_search_cursor`, `idx_users_name_active`

### Testing
- **Integration Tests**: `api_tests/search_users_test.go`
- **Unit Tests**: `internal/domain/usecase/user/search_test.go`

### Proto
- **Service**: `github.com/rshelekhov/sso-protos/gen/go/api/user/v1`
- **Messages**: `SearchUsersRequest`, `SearchUsersResponse`

---

## Configuration

### gRPC Endpoint
- **Host**: `localhost:44044`
- **Service**: `user.v1.UserService/SearchUsers`
- **Config**: `config/config.yaml`

### Database
- **PostgreSQL**: `localhost:5432` (sso_dev)
- **MongoDB**: `localhost:27017`
- **Credentials**: See `config/config.yaml`

### Observability
- **Logs**: `docker compose logs -f sso | grep SearchUsers`
- **Grafana**: `http://localhost:3000`
- **Prometheus**: `http://localhost:9090`

---

## Next Steps (Prioritized)

### HIGH Priority
1. **Deployment Preparation**
   - Review production configuration
   - Verify database migrations
   - Plan rollout strategy

2. **Monitoring & Alerting**
   - Set up Grafana dashboards
   - Configure Prometheus alerts
   - Define SLOs (latency, error rate)

### MEDIUM Priority
3. **Performance Testing**
   - Load testing in staging
   - Query profiling and optimization
   - Connection pool tuning

4. **Additional Testing**
   - Security audit
   - Compliance validation
   - Chaos engineering

### LOW Priority
5. **Future Enhancements**
   - Fuzzy search (pg_trgm)
   - Result caching (Redis)
   - Advanced filtering

6. **Documentation Updates**
   - Client SDK examples
   - Troubleshooting guides
   - Runbooks for operations

---

## Support & Troubleshooting

### Common Issues

**Internal Server Error**
- Check logs: `docker compose logs sso --tail=200 | grep -i error`
- Verify database migration applied: `SELECT * FROM schema_migrations;`
- Check database indexes: `\d users` in psql

**Unauthenticated Error**
- Verify JWT token is valid and not expired
- Check authorization header format: `Bearer <token>`

**Invalid Page Token**
- Ensure page_token is from a previous response
- Token must be base64-encoded cursor

### Logs
```bash
# View SearchUsers logs
docker compose logs sso | grep SearchUsers

# View error logs
docker compose logs sso | grep "level=ERROR"

# Follow logs in real-time
docker compose logs -f sso
```

### Database Verification
```bash
# Connect to database
psql -U root -d sso_dev -h localhost

# Verify indexes exist
\d users

# Test search query
SELECT COUNT(*) FROM users
WHERE deleted_at IS NULL
  AND (email ILIKE '%john%' OR name ILIKE '%john%');
```

---

## Document Maintenance

**Last Updated**: 2025-11-07

**Maintainers**: Development Team

**Update Policy**:
- Update when implementation changes
- Keep examples current with latest versions
- Sync with actual configuration

---

## Complete Documentation

For the comprehensive implementation summary including full details on architecture, testing, deployment, and metrics:

👉 **See**: `IMPLEMENTATION_SUMMARY_SearchUsers.md`

This document contains:
- 10 comprehensive sections covering all aspects
- 1,224 lines of detailed documentation
- Complete code change history
- Testing procedures
- Deployment instructions
- Prioritized next steps

---

**Ready for production deployment and team handoff** ✅
