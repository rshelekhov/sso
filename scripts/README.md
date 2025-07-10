# MinIO Initialization Scripts

## minio-init.sh

Script for initializing MinIO S3 storage on docker-compose startup.

### What it does:

1. **Configures MinIO client** to connect to local MinIO instance
2. **Creates bucket `sso-keys`** for storing PEM keys
3. **Uploads PEM key** `app_test-client-id_private.pem` to bucket (if file exists)
4. **Lists bucket contents** for verification

### Usage:

Script runs automatically through docker-compose service `minio-init`:

```bash
docker-compose up -d
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
docker-compose logs minio-init
```

### Requirements:

- MinIO must be running and healthy
- PEM key must be located at `./certs/app_test-client-id_private.pem`
- Credentials: `minio_user:minio_password`
