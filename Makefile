.PHONY: migrate db-insert build test

setup: migrate db-insert build

# Run migrations
migrate:
	@echo "Running migrations..."
	@migrate -database $(POSTGRESQL_URL) -path migrations up
	@echo "Migrations completed."

# Insert into database the test app with this data
db-insert:
	@echo "Inserting test data into the database..."
	@psql $(POSTGRESQL_URL) -c "INSERT INTO apps (id, name, secret, status, created_at, updated_at) VALUES ('test-app-id', 'test', 'test-secret', 1, NOW(), NOW()) ON CONFLICT DO NOTHING;"
	@echo "Test data inserted."

# Build server
build:
	@echo "Building the server..."
	@go build -v ./cmd/sso
	@echo "Server built."

# Run tests
test: setup
	@echo "Running tests..."
	@go test ./...
	@echo "Tests completed."