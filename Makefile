CONFIG_PATH ?= ./config/.env
SERVER_PORT ?= 44044

# Supported types: postgres, mongo
DB_TYPE ?= postgres

# Don't forget to set POSTGRESQL_URL or MONGO_URL with your credentials
POSTGRESQL_URL ?= postgres://root:password@localhost:5432/sso_dev?sslmode=disable
MONGO_URL ?= mongodb://root:password@localhost:27017/sso_dev

.PHONY: setup-dev setup-dev-with-postgres migrate-postgres migrate-postgres-down db-postgres-insert db-mongo-insert run-server stop-server build test-all-app test-api lint

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
		@if psql $(POSTGRESQL_URL) -c "SELECT 1 FROM pg_tables WHERE tablename = 'apps';" | grep -q 1; then \
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
		@if psql $(POSTGRESQL_URL) -c "SELECT 1 FROM apps WHERE id = 'test-app-id';" | grep -q 1; then \
    		echo "Test data already inserted. No need to insert."; \
    	else \
    		echo "Inserting test data into the database..."; \
    		psql $(POSTGRESQL_URL) -c "INSERT INTO apps (id, name, secret, status, created_at, updated_at) VALUES ('test-app-id', 'test', 'test-secret', 1, NOW(), NOW()) ON CONFLICT DO NOTHING;"; \
    		echo "Test data inserted."; \
    	fi

# Insert test data in mongo only if not already inserted
db-mongo-insert:
	@echo "Checking if test data needs to be inserted into MongoDB..."
	@if mongo $(MONGO_URL) --quiet --eval 'db.apps.findOne({_id: "test-app-id"})' | grep -q "null"; then \
		echo "Inserting test data into MongoDB..."; \
		mongo $(MONGO_URL) --eval 'db.apps.insertOne({_id: "test-app-id", name: "test", secret: "test-secret", status: 1, created_at: new Date(), updated_at: new Date()})'; \
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

# Run tests
test-all-app: setup-dev run-server
	@echo "Running tests..."
	@go test -v -timeout 60s -parallel=1 ./...
	@echo "Tests completed."

test-api: setup-dev run-server
	@echo "Running tests..."
	@go test -v -timeout 60s -parallel=1 ./api_tests
	@echo "Tests completed."


# Run linters
lint:
	@echo "Running linters..."
	golangci-lint run --fix
	@echo "Linters completed."

.DEFAULT_GOAL := build