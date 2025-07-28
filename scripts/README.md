# Scripts

## minio-init.sh

Script for initializing MinIO S3 storage on docker compose startup.

### What it does:

1. **Configures MinIO client** to connect to local MinIO instance
2. **Creates bucket `sso-keys`** for storing PEM keys
3. **Uploads PEM key** `app_test-client-id_private.pem` to bucket (if file exists)
4. **Lists bucket contents** for verification

### Usage:

Script runs automatically through docker compose service `minio-init`:

```bash
docker compose up -d
```

### Structure in MinIO:

```
sso-keys/
└── keys/
    └── app_test-client-id_private.pem
```

### Logs:

View initialization logs:

```bash
docker compose logs minio-init
```

### Requirements:

- MinIO must be running and healthy
- PEM key must be located at `./certs/app_test-client-id_private.pem`
- Credentials: `minio_user:minio_password`

## test-entrypoint.sh

Script for running the complete test suite in a Docker environment.

### What it does:

1. **Runs database migrations** using migrate tool against PostgreSQL
2. **Inserts test client** into database with predefined credentials
3. **Starts SSO application** in background mode
4. **Waits for app startup** by checking gRPC port (44044)
5. **Executes all tests** including unit tests and API integration tests

### Usage:

Script is designed to run inside Docker container:

```bash
./scripts/test-entrypoint.sh
```

Or through Docker compose for testing:

```bash
docker compose -f docker-compose.ci.yaml up --build
```

### Test client configuration:

```
ID: test-client-id
Name: test
Secret: test-secret
Status: 1 (active)
```

### Requirements:

- PostgreSQL database running at `postgres:5432`
- Database credentials: `sso_user:sso_password`
- Database name: `sso_db`
- All migration files in `./migrations/` directory
- SSO application source code available

### Timeout:

- App startup timeout: 30 seconds
- Connection check: telnet to localhost:44044
