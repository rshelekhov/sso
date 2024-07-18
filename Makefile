CONFIG_PATH ?= ./config/.env
SERVER_PORT ?= 44044

# Don't forget to set POSTGRESQL_URL with your credentials
POSTGRESQL_URL ?='postgres://app:p%40ssw0rd@localhost:5432/sso_dev?sslmode=disable'

.PHONY: migrate migrate-down db-insert run-server stop-server test test-upd

setup: migrate db-insert run-server

# Run migrations only if not already applied
migrate:
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
test-all-app: setup
	@echo "Running tests..."
	@go test -v -json -timeout 60s ./... > test_results.json
	@echo "Tests completed."

test-api: setup
	@go test -v -json -timeout 60s ./api_tests > api_test_results.json