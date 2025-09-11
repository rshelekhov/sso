#!/bin/sh
set -e

echo "Running database migrations..."
migrate -database 'postgres://sso_user:sso_password@postgres:5432/sso_db?sslmode=disable' -path migrations up

echo "Adding test client..."
psql 'postgres://sso_user:sso_password@postgres:5432/sso_db' -c \
  "INSERT INTO clients (id, name, secret, status, created_at, updated_at) 
   VALUES ('test-client-id', 'test', 'test-secret', 1, NOW(), NOW()) 
   ON CONFLICT DO NOTHING;"

echo "Starting SSO app..."
CONFIG_PATH=/src/config/config.ci.yaml go run ./cmd/sso > /tmp/sso.log 2>&1 &

echo "Waiting for app to start..."
for i in $(seq 1 30); do
  if timeout 1 sh -c 'echo "" | telnet localhost 44044' 2>/dev/null | grep -q "Connected"; then
    echo 'App is ready!'
    break
  fi
  echo "Waiting... ($i/30)"
  sleep 1
done

echo "Running tests..."
go test -v ./internal/... ./api_tests
TEST_EXIT_CODE=$?

# Always show SSO app logs
echo "=== SSO Application Logs ==="
cat /tmp/sso.log || echo "No SSO logs found"

# Show last few lines of app logs if still running
if pgrep -f "go run ./cmd/sso" > /dev/null; then
    echo "=== App still running, showing recent logs ==="
    tail -50 /tmp/sso.log 2>/dev/null || echo "Could not tail logs"
fi

# Exit with the test exit code
exit $TEST_EXIT_CODE 