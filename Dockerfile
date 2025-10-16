# Stage 1: Build the application
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Setup base software for building an app
RUN apk update && apk add --no-cache ca-certificates git make

# Install golang-migrate
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download -x && go mod verify

# Copy application source
COPY . .

# Build the application
RUN go build -o /app ./cmd/sso

# Stage 2: Test stage
FROM builder AS tester

ENV CONFIG_PATH=/src/config/config.docker.yaml
ENV RUN_TESTS=true

# Install postgresql and busybox-extras for database setup and port checks
RUN apk add --no-cache postgresql busybox-extras

# Copy and make executable the test script
COPY scripts/test-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/test-entrypoint.sh

CMD ["test-entrypoint.sh"]

# Stage 3: Prepare the final runtime image
FROM alpine:3.19 AS runner

RUN apk update && apk add --no-cache ca-certificates make postgresql-client busybox-extras curl

# Install mongosh for MongoDB support
RUN curl -fsSL https://downloads.mongodb.com/compass/mongosh-1.10.6-linux-x64.tgz | tar -xz -C /tmp && \
    mv /tmp/mongosh-1.10.6-linux-x64/bin/mongosh /usr/local/bin/ && \
    chmod +x /usr/local/bin/mongosh && \
    rm -rf /tmp/mongosh-*

WORKDIR /src

COPY --from=builder /app ./sso
COPY --from=builder /src/Makefile ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/static ./static
COPY --from=builder /src/config ./config
COPY --from=builder /go/bin/migrate /usr/local/bin/migrate

EXPOSE 44044

CMD ["./sso"]