# Stage 1: Build the application
FROM golang:1.22-alpine3.19 AS builder

WORKDIR /src

# Setup base software for building an app
RUN apk update && apk add --no-cache ca-certificates git make

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download -x && go mod verify

# Copy application source
COPY . .

# Build the application
RUN go build -o /app ./cmd/sso

# Stage 2: Prepare the final runtime image
FROM alpine:3.19 AS runner

RUN apk update && apk add --no-cache ca-certificates make postgresql-client
# RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
RUN curl -L https://github.com/golang-migrate/migrate/releases/download/v4.12.2/migrate.linux-amd64.tar.gz | tar xvz

WORKDIR /src

COPY --from=builder /app ./
COPY --from=builder /src/Makefile ./

CMD ["./app"]