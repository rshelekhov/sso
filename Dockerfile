# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

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

# Install postgresql and busybox-extras for database setup and port checks
RUN apk add --no-cache postgresql busybox-extras

# Copy and make executable the test script
COPY scripts/test-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/test-entrypoint.sh

CMD ["test-entrypoint.sh"]

# Stage 3: Prepare the final runtime image
FROM alpine:3.19 AS runner

RUN apk update && apk add --no-cache ca-certificates make postgresql-client

WORKDIR /src

COPY --from=builder /app ./
COPY --from=builder /src/Makefile ./
COPY --from=builder /src/migrations ./migrations
COPY --from=builder /src/static ./static
COPY --from=builder /go/bin/migrate /usr/local/bin/migrate

CMD ["./app"]