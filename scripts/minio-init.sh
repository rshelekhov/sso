#!/bin/bash

# MinIO Init Script
# Creates bucket and uploads PEM key for SSO service

set -e

echo "Starting MinIO initialization..."

# Configure MinIO client
echo "Configuring MinIO client..."
mc alias set local http://minio:9000 minio_user minio_password

# Wait for MinIO to be ready
echo "Waiting for MinIO to be ready..."
until mc alias set local http://minio:9000 minio_user minio_password; do
  echo "MinIO is not ready yet, retrying in 2 seconds..."
  sleep 2
done

echo "MinIO is ready!"

# Create bucket
echo "Creating bucket..."
mc mb local/sso --ignore-existing

echo "Setting bucket policy to private..."
mc anonymous set none local/sso

# Upload PEM files
echo "Uploading PEM files..."
if [ -d "/certs" ] && [ -n "$(ls -A /certs 2>/dev/null)" ]; then
    for pem_file in /certs/*.pem; do
        if [ -f "$pem_file" ]; then
            filename=$(basename "$pem_file")
            echo "Uploading $filename..."
            mc cp "$pem_file" "local/sso/keys/$filename"
        fi
    done
    echo "All PEM files uploaded successfully!"
else
    echo "Warning: No PEM files found in /certs directory"
fi

echo "MinIO initialization completed!" 