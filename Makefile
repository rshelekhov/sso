# ================================
# Configuration
# ================================

CONFIG_PATH ?= ./config/config.example.yaml
SERVER_PORT ?= 44044

# Supported types: postgres, mongo
DB_TYPE ?= postgres
POSTGRESQL_URL ?= postgres://root:password@localhost:5432/sso_dev?sslmode=disable
# MONGO_URL ?= mongodb://localhost:27017/sso_dev
DOCKER_COMPOSE_SERVICES ?= postgres redis minio minio-init otel-collector loki prometheus tempo grafana promtail # add mongo if you want to test with mongo

.PHONY: help build setup-dev run stop test-local test-docker test-docker-clean test-ci lint observability obs-check

# ================================
# Main Commands
# ================================

# Build the application
build:
	go build -v ./cmd/sso

# Setup local development environment
setup-dev:
ifeq ($(DB_TYPE), postgres)
	$(MAKE) _setup-postgres
else ifeq ($(DB_TYPE), mongo)  
	$(MAKE) _setup-mongo
else
	@echo "ERROR: Unsupported DB_TYPE='$(DB_TYPE)'. Use 'mongo' or 'postgres'."
	exit 1
endif

# Run server locally
run: stop
	@echo "Running server on port $(SERVER_PORT)..."
	@CONFIG_PATH=$(CONFIG_PATH) go run ./cmd/sso &
	@sleep 3
	@while ! nc -z localhost $(SERVER_PORT); do sleep 1; done
	@echo "Server running (PID: $$(lsof -t -i :$(SERVER_PORT)))"

# Stop server
stop:
	@PID=$$(lsof -t -i :$(SERVER_PORT) 2>/dev/null); \
	if [ -n "$$PID" ]; then kill $$PID; echo "Server stopped."; fi

# ================================  
# Testing
# ================================

# Run tests locally (setup + server + test)
test-local: setup-dev run
	@go test -v -timeout 300s -parallel=4 ./...

# Run Docker-based tests (full stack + observability)
test-docker:
	@echo "Starting Docker test environment..."
	@docker compose up -d $(DOCKER_COMPOSE_SERVICES)
	@sleep 15
	@echo "Building and running tests in Docker..."
	@docker build --target tester -t sso-test .
	@docker run --network sso_default sso-test
	@echo "Tests completed. Grafana: http://localhost:3000 (admin/admin)"

# Stop Docker test environment  
test-docker-clean:
	@docker compose down

# CI tests (minimal Docker setup)
test-ci:
	@docker compose -f docker-compose.ci.yaml up -d
	@sleep 20
	@$(MAKE) _docker-setup
	@go test -v -timeout 300s ./internal/...
	@CONFIG_PATH=./config/config.ci.yaml go run ./cmd/sso &
	@SERVER_PID=$$!; sleep 10; \
	CONFIG_PATH=./config/config.ci.yaml go test -v -timeout 300s ./api_tests; \
	TEST_RESULT=$$?; kill $$SERVER_PID 2>/dev/null || true; \
	docker compose -f docker-compose.ci.yaml down -v; exit $$TEST_RESULT

# ================================
# Observability  
# ================================

# Start observability stack
observability:
	@docker compose up -d prometheus loki tempo otel-collector grafana
	@sleep 20
	@echo "Observability started: http://localhost:3000 (admin/admin)"

# Check observability health + view traces
obs-check:
	@echo "=== Service Health ==="
	@curl -sf http://localhost:9090/-/healthy >/dev/null && echo "✓ Prometheus" || echo "✗ Prometheus"
	@curl -sf http://localhost:3100/ready >/dev/null && echo "✓ Loki" || echo "✗ Loki" 
	@curl -sf http://localhost:3200/ready >/dev/null && echo "✓ Tempo" || echo "✗ Tempo"
	@curl -sf http://localhost:3000/api/health >/dev/null && echo "✓ Grafana" || echo "✗ Grafana"
	@curl -sf http://localhost:13133 >/dev/null && echo "✓ OTEL Collector" || echo "✗ OTEL Collector"
	@nc -z localhost 44044 2>/dev/null && echo "✓ SSO Server" || echo "✗ SSO Server"
	@echo "=== Telemetry Check ==="
	@curl -s "http://localhost:8889/metrics" | grep -q "otelcol_receiver_accepted" && echo "✓ OTEL receiving data" || echo "✗ No telemetry data"
	@curl -s "http://localhost:9090/api/v1/targets" | grep -q "otel-collector" && echo "✓ Prometheus scraping" || echo "✗ Scraping issues"
	@echo "=== Recent Traces ==="
	@curl -s "http://localhost:3200/api/search?limit=3" | jq -r '.traces[]? | "TraceID: \(.traceID) | \(.rootServiceName) | \(.durationMs)ms"' 2>/dev/null || echo "No traces found"
	@echo "=== Access ==="
	@echo "Grafana: http://localhost:3000 (admin/admin) | Prometheus: http://localhost:9090"

# ================================
# Utility
# ================================

# Run linters
lint:
	golangci-lint run --fix

# Show help
help:
	@echo "SSO Makefile Commands:"
	@echo ""
	@echo "Development:"
	@echo "  build             - Build application"
	@echo "  setup-dev         - Setup local development environment" 
	@echo "  run               - Run server locally"
	@echo "  stop              - Stop server"
	@echo ""
	@echo "Testing:"
	@echo "  test-local        - Local tests (setup + run + test)"
	@echo "  test-docker       - Docker tests with full observability stack"
	@echo "  test-docker-clean - Stop Docker environment"
	@echo "  test-ci           - CI tests (minimal Docker)"
	@echo ""
	@echo "Observability:"
	@echo "  observability     - Start observability stack"
	@echo "  obs-check         - Check health + show traces"
	@echo ""
	@echo "Other:"
	@echo "  lint              - Run linters"
	@echo "  help              - This help"
	@echo ""
	@echo "Variables: DB_TYPE={postgres|mongo}, CONFIG_PATH, SERVER_PORT"

# ================================
# Internal Helpers
# ================================

_setup-postgres:
	@if ! which psql >/dev/null 2>&1; then \
		echo "Installing postgresql-client..."; \
		if [ "$$(uname)" = "Darwin" ]; then brew install postgresql; \
		else sudo apt-get update && sudo apt-get install -y postgresql-client; fi \
	fi
	@if ! psql $(POSTGRESQL_URL) -c "SELECT 1 FROM pg_tables WHERE tablename = 'clients';" | grep -q 1; then \
		echo "Running migrations..."; \
		migrate -database $(POSTGRESQL_URL) -path migrations up; \
	fi
	@if ! psql $(POSTGRESQL_URL) -c "SELECT 1 FROM clients WHERE id = 'test-client-id';" | grep -q 1; then \
		echo "Inserting test data..."; \
		psql $(POSTGRESQL_URL) -c "INSERT INTO clients (id, name, secret, status, created_at, updated_at) VALUES ('test-client-id', 'test', 'test-secret', 1, NOW(), NOW());"; \
	fi

_setup-mongo:
	@if [ "$$(mongosh "$(MONGO_URL)" --quiet --eval 'db.clients.countDocuments({_id: "test-client-id"})')" = "0" ]; then \
		mongosh "$(MONGO_URL)" --eval 'db.clients.insertOne({_id: "test-client-id", name: "test", secret: "test-secret", status: 1, created_at: new Date(), updated_at: new Date()})'; \
	fi

_docker-setup:
	@migrate -database "postgres://sso_user:sso_password@localhost:5432/sso_db?sslmode=disable" -path migrations up || true
	@psql "postgres://sso_user:sso_password@localhost:5432/sso_db" -c "INSERT INTO clients (id, name, secret, status, created_at, updated_at) VALUES ('test-client-id', 'test', 'test-secret', 1, NOW(), NOW()) ON CONFLICT DO NOTHING;" || true
	@for i in {1..30}; do \
		if docker compose logs minio-init | grep -q "MinIO initialization completed"; then break; fi; \
		echo "Waiting for MinIO... ($$i/30)"; sleep 2; \
	done

.DEFAULT_GOAL := help