CONFIG_PATH ?= ./config/.env
SERVER_PORT ?= 44044

# Don't forget to set POSTGRESQL_URL with your credentials
POSTGRESQL_URL ?= postgres://root:password@localhost:5432/sso_dev?sslmode=disable

.PHONY: setup setup-dev migrate migrate-down db-insert run-server stop-server test-all-app test-api

setup: migrate

# Run migrations and insert data to the database (only for local and dev)
setup-dev: migrate db-insert

# Run migrations only if not already applied
migrate:
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

	@echo "Checking if golang-migrate is installed..."
	@if ! which migrate > /dev/null 2>&1; then \
		echo "golang-migrate not found. Installing..."; \
		go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest; \
	else \
		echo "golang-migrate is already installed."; \
	fi

	@echo "Checking if migrations are needed..."
		@if psql $(POSTGRESQL_URL) -c "SELECT 1 FROM pg_tables WHERE tablename = 'apps';" | grep -q 1; then \
			echo "Migrations are not needed."; \
		else \
			echo "Running migrations..."; \
			migrate -database $(POSTGRESQL_URL) -path migrations up; \
			echo "Migrations completed."; \
		fi

# Rollback migrations
migrate-down:
	@echo "Rolling back migrations..."
	@migrate -database $(POSTGRESQL_URL) -path migrations down
	@echo "Migrations rolled back."

# Insert test data only if not already inserted
db-insert:
	@echo "Checking if test data needs to be inserted..."
		@if psql $(POSTGRESQL_URL) -c "SELECT 1 FROM apps WHERE id = 'test-app-id';" | grep -q 1; then \
    		echo "Test data already inserted. No need to insert."; \
    	else \
    		echo "Inserting test data into the database..."; \
    		psql $(POSTGRESQL_URL) -c "INSERT INTO apps (id, name, secret, status, created_at, updated_at) VALUES ('test-app-id', 'test', 'test-secret', 1, NOW(), NOW()) ON CONFLICT DO NOTHING;"; \
    		echo "Test data inserted."; \
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

# Run tests
test-all-app: setup-dev run-server
	@echo "Running tests..."
	@go test -v -timeout 60s ./...
	@echo "Tests completed."

test-api: setup-dev run-server
	@echo "Running tests..."
	@go test -v -timeout 60s ./api_tests
	@echo "Tests completed."