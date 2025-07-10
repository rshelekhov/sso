# ================================
# Configuration
# ================================

# Local development configuration
CONFIG_PATH ?= ./config/config.yaml
SERVER_PORT ?= 44044

# Supported types: postgres, mongo
DB_TYPE ?= postgres

# Don't forget to set POSTGRESQL_URL or MONGO_URL with your credentials
POSTGRESQL_URL ?= postgres://root:password@localhost:5432/sso_dev?sslmode=disable
MONGO_URL ?= mongodb://localhost:27017/sso_dev

# Docker test configuration
DOCKER_TEST_CONFIG_PATH ?= ./config/config.test.yaml
DOCKER_COMPOSE_SERVICES ?= postgres redis mongo minio otel-collector loki prometheus

.PHONY: setup-dev setup-dev-with-postgres migrate-postgres migrate-postgres-down db-postgres-insert db-mongo-insert run-server stop-server build test-all-app test-api test-docker-setup test-docker-api test-docker-unit test-docker-all test-docker-cleanup test-docker-full test-docker-status help lint

# Setup dev environment with the selected database
setup-dev:
ifeq ($(DB_TYPE), postgres)
	$(MAKE) setup-dev-with-postgres
else ifeq ($(DB_TYPE), mongo)
	$(MAKE) setup-dev-with-mongo
else
	@echo "ERROR: Unsupported DB_TYPE='$(DB_TYPE)'. Use 'mongo' or 'postgres'."
	exit 1
endif

# Run migrations and insert data to the postgres database (only for local and dev)
setup-dev-with-postgres: migrate-postgres db-postgres-insert

# Run migrations and insert data to the mongo database (only for local and dev)
setup-dev-with-mongo: db-mongo-insert

# Run migrations only if not already applied
migrate-postgres:
	@echo "Checking if postgresql-client is installed..."
	@if ! which psql > /dev/null 2>&1; then \
		echo "postgresql-client not found. Installing..."; \
		if [ "$$(uname)" = "Darwin" ]; then \
			echo "Detected macOS. Installing via Homebrew..."; \
			brew install postgresql; \
		elif [ "$$(uname)" = "Linux" ]; then \
			echo "Detected Linux. Installing via apt-get..."; \
			sudo apt-get update && sudo apt-get install -y postgresql-client; \
		else \
			echo "Unsupported OS. Please install postgresql-client manually."; \
			exit 1; \
		fi \
	else \
		echo "postgresql-client is already installed."; \
	fi

	@echo "Checking if migrations are needed..."
		@if psql $(POSTGRESQL_URL) -c "SELECT 1 FROM pg_tables WHERE tablename = 'clients';" | grep -q 1; then \
			echo "Migrations are not needed."; \
		else \
			echo "Running migrations..."; \
			migrate -database $(POSTGRESQL_URL) -path migrations up; \
			echo "Migrations completed."; \
		fi

# Rollback migrations
migrate-postgres-down:
	@echo "Rolling back migrations..."
	@migrate -database $(POSTGRESQL_URL) -path migrations down
	@echo "Migrations rolled back."

# Insert test data in postgres only if not already inserted
db-postgres-insert:
	@echo "Checking if test data needs to be inserted..."
		@if psql $(POSTGRESQL_URL) -c "SELECT 1 FROM clients WHERE id = 'test-client-id';" | grep -q 1; then \
    		echo "Test data already inserted. No need to insert."; \
    	else \
    		echo "Inserting test data into the database..."; \
    		psql $(POSTGRESQL_URL) -c "INSERT INTO clients (id, name, secret, status, created_at, updated_at) VALUES ('test-client-id', 'test', 'test-secret', 1, NOW(), NOW()) ON CONFLICT DO NOTHING;"; \
    		echo "Test data inserted."; \
    	fi

# Insert test data in mongo only if not already inserted
db-mongo-insert:
	@echo "Checking if test data needs to be inserted into MongoDB..."
	@if [ "$$(mongosh "$(MONGO_URL)" --quiet --eval 'db.clients.countDocuments({_id: "test-client-id"})')" = "0" ]; then \
		echo "Inserting test data into MongoDB..."; \
		mongosh "$(MONGO_URL)" --eval 'db.clients.insertOne({_id: "test-client-id", name: "test", secret: "test-secret", status: 1, created_at: new Date(), updated_at: new Date()})'; \
		echo "Test data inserted."; \
	else \
		echo "Test data already exists in MongoDB. No need to insert."; \
	fi

# Run server
run-server: stop-server
	@echo "Running the server..."
	@CONFIG_PATH=$(CONFIG_PATH) go run github.com/rshelekhov/sso/cmd/sso &
	@sleep 5 # Wait for the server to start
	@while ! nc -z localhost $(SERVER_PORT); do \
		echo "Waiting for server to be ready..."; \
		sleep 1; \
	done
	@echo "Server is running with PID $$(lsof -t -i :$(SERVER_PORT))."

# Stop server
stop-server:
	@echo "Stopping the server..."
	@PID=$$(lsof -t -i :$(SERVER_PORT)); \
    	if [ -n "$$PID" ]; then \
    		kill $$PID; \
    		echo "Server stopped."; \
    	else \
    		echo "No server is running on port $(SERVER_PORT)."; \
    	fi

build:
	go build -v ./cmd/sso

# ================================
# Local Test Commands
# ================================

# Run all tests locally (setup local DB + run server + test)
test-all-app: setup-dev run-server
	@echo "Running all tests locally..."
	@go test -v -timeout 300s -parallel=4 ./...
	@echo "Local tests completed."

# Run API tests locally (setup local DB + run server + test)
test-api: setup-dev run-server
	@echo "Running API tests locally..."
	@go test -v -timeout 300s -parallel=4 ./api_tests
	@echo "Local API tests completed."

# ================================
# Docker Test Commands
# ================================

# Setup Docker infrastructure for tests
test-docker-setup:
	@echo "Starting Docker infrastructure for tests..."
	@docker-compose up -d $(DOCKER_COMPOSE_SERVICES)
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "Checking service readiness..."
	@for i in {1..30}; do \
		if docker-compose ps | grep -E "(postgres|redis)" | grep -q "Up"; then \
			echo "Services are ready!"; \
			break; \
		fi; \
		echo "Waiting for services... ($$i/30)"; \
		sleep 2; \
	done
	@echo "Docker infrastructure setup completed."

# Run API tests against Docker infrastructure
test-docker-api:
	@echo "Running API tests against Docker infrastructure..."
	@echo "Using config: $(DOCKER_TEST_CONFIG_PATH)"
	@CONFIG_PATH=$(DOCKER_TEST_CONFIG_PATH) go test -v -timeout 300s -parallel=4 ./api_tests
	@echo "Docker API tests completed."

# Run unit tests (don't require Docker)
test-docker-unit:
	@echo "Running unit tests..."
	@go test -v -timeout 300s -parallel=4 ./internal/...
	@echo "Unit tests completed."

# Run all tests against Docker infrastructure
test-docker-all: test-docker-unit test-docker-api
	@echo "All Docker tests completed."

# Stop Docker infrastructure
test-docker-cleanup:
	@echo "Stopping Docker infrastructure..."
	@docker-compose down
	@echo "Docker infrastructure stopped."

# Full Docker test cycle: setup + test + cleanup
test-docker-full: test-docker-setup test-docker-all test-docker-cleanup
	@echo "Full Docker test cycle completed."

# Check Docker infrastructure status
test-docker-status:
	@echo "Checking Docker infrastructure status..."
	@docker-compose ps $(DOCKER_COMPOSE_SERVICES)

# ================================
# CI/CD Commands
# ================================

# Run tests in CI environment using docker-compose.ci.yaml
test-ci:
	@echo "Running CI tests with minimal Docker infrastructure..."
	@docker-compose -f docker-compose.ci.yaml up -d
	@echo "Waiting for services to be ready..."
	@sleep 30
	@echo "Running migrations..."
	@migrate -database "postgres://sso_user:sso_password@localhost:5432/sso_db?sslmode=disable" -path migrations up || true
	@echo "Setting up test client data..."
	@psql "postgres://sso_user:sso_password@localhost:5432/sso_db" -c "INSERT INTO clients (id, name, secret, status, created_at, updated_at) VALUES ('test-client-id', 'test', 'test-secret', 1, NOW(), NOW()) ON CONFLICT DO NOTHING;" || true
	@echo "Waiting for MinIO initialization to complete..."
	@docker-compose -f docker-compose.ci.yaml logs minio-init | grep -q "MinIO initialization completed" || sleep 5
	@echo "Running unit tests..."
	@go test -v -timeout 300s -parallel=4 ./internal/...
	@echo "Starting SSO server for API tests..."
	@CONFIG_PATH=./config/config.ci.yaml go run ./cmd/sso &
	@SERVER_PID=$$!; \
	echo "Waiting for server to start..."; \
	sleep 10; \
	while ! nc -z localhost 44044; do \
		echo "Waiting for server to be ready..."; \
		sleep 1; \
	done; \
	echo "Running API tests..."; \
	CONFIG_PATH=./config/config.ci.yaml go test -v -timeout 300s -parallel=4 ./api_tests; \
	TEST_RESULT=$$?; \
	echo "Stopping SSO server..."; \
	kill $$SERVER_PID 2>/dev/null || true; \
	echo "Cleaning up..."; \
	docker-compose -f docker-compose.ci.yaml down -v; \
	if [ $$TEST_RESULT -eq 0 ]; then \
		echo "CI tests completed successfully."; \
	else \
		echo "CI tests failed."; \
		exit $$TEST_RESULT; \
	fi

# ================================
# Utility Commands
# ================================

# Show help
help:
	@echo "SSO Makefile Commands:"
	@echo ""
	@echo "BUILD:"
	@echo "  build                 - Build the SSO application"
	@echo ""
	@echo "LOCAL DEVELOPMENT:"
	@echo "  setup-dev             - Setup local development environment"
	@echo "  run-server            - Run SSO server locally"
	@echo "  stop-server           - Stop local SSO server"
	@echo ""
	@echo "LOCAL TESTS:"
	@echo "  test-all-app          - Run all tests locally (setup DB + server + test)"
	@echo "  test-api              - Run API tests locally (setup DB + server + test)"
	@echo ""
	@echo "DOCKER TESTS:"
	@echo "  test-docker-setup     - Start Docker infrastructure for tests"
	@echo "  test-docker-api       - Run API tests against Docker infrastructure"
	@echo "  test-docker-unit      - Run unit tests (no Docker required)"
	@echo "  test-docker-all       - Run all tests against Docker infrastructure"
	@echo "  test-docker-cleanup   - Stop Docker infrastructure"
	@echo "  test-docker-full      - Full cycle: setup + test + cleanup"
	@echo "  test-docker-status    - Check Docker infrastructure status"
	@echo ""
	@echo "CI/CD:"
	@echo "  test-ci               - Run tests in CI environment (minimal Docker)"
	@echo ""
	@echo "MIGRATIONS:"
	@echo "  migrate-postgres      - Run PostgreSQL migrations"
	@echo "  migrate-postgres-down - Rollback PostgreSQL migrations"
	@echo ""
	@echo "OTHER:"
	@echo "  lint                  - Run linters"
	@echo "  help                  - Show this help message"
	@echo ""
	@echo "VARIABLES:"
	@echo "  CONFIG_PATH           - Path to config file (default: ./config/config.yaml)"
	@echo "  DB_TYPE               - Database type: postgres or mongo (default: postgres)"
	@echo "  DOCKER_TEST_CONFIG_PATH - Config for Docker tests (default: ./config/config.test.yaml)"

# Run linters
lint:
	@echo "Running linters..."
	golangci-lint run --fix
	@echo "Linters completed."

.DEFAULT_GOAL := help