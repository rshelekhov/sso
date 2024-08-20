# gRPC SSO app

Typically, the term “Auth” refers to services that are responsible only for authorization and authentication, while “SSO” (Single Sign-On) is a more general concept that includes working with permissions, providing user information, and more.

Of course, there are more precise definitions for these types of services, but in my practical experience, the boundaries have always been blurred or even erased.

To clarify, I use the term SSO to describe a service that combines three important functions:

1. Authorization and authentication
2. Working with permissions
3. Providing user information

Currently, the application implements functions 1 and 3.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

Backend is written in GO, so I suggest you have installed [Golang](https://golang.org).

Also, you need to install [golang-migrate](https://github.com/golang-migrate/migrate) tool for running database migrations.

And the last one, you need to have `psql` (PostgreSQL interactive terminal), because this tool  is used in the commands described in the makefile.

### Installing

Add config file to `./config/.env` (see an example in the `./config/.env.example`).

- By default, this app use port `44044`. If you set another port please update `SERVER_PORT` in the `Makefile` as well.

Set path to config:
```bash
export CONFIG_PATH=./config/.env
```

Set URL for PostgresQL:
```bash
export POSTGRESQL_URL='postgres://login:password@host:port/db_name?sslmode=disable'
```

Run migrations using `make migrate` command.

Then run the app using make `run-server` command.

## Running the tests

For testing the functionality of the application, both unit tests for individual functions and end-to-end tests for checking the entire application are used.

### Break down into end-to-end tests

End-to-end tests are conducted using the black-box method. During the test run, a client is created that connects to the gRPC service and sends real requests to it.

If you use S3 for key storage you need to copy `app_test-app-id_private.pem` from the `certs` folder and upload to your S3 bucket.

Run tests — `make test-all-app` or `make test-api`. You'll run database migrations (or check if you did it before), insert test-app into database, run the server and then run tests.

For more details you can see other commands in the `Makefile`.

### And coding style tests

Explain what these tests test and why
add details about linters

```
Give an example
```

## Deployment

To deploy the application on your server, you can download the latest image from Docker Hub directly to your server. To do this, you need to connect to the server via SSH and ensure that Docker is installed. Then, execute the following command:
```
docker pull rshelekhov/grpc-sso:latest
```

To run the container, you need to place a config file in a volume and set values for the `CONFIG_PATH` and `POSTGRESQL_URL` variables. Additionally, you need to specify the port in the docker run command parameters. Here’s an example command to run the container:
```
docker run -d \
  -v ${PWD}/config/grpc-sso:/src/config \
  -e CONFIG_PATH=/src/config/.env \
  -e POSTGRESQL_URL=postgres://user:password@127.0.0.1:5432/sso_dev?sslmode=disable \
  -p 44044:44044 \
  --name sso-app \
  grpc-sso:latest
```

You can also check the settings for GitHub Actions in the `.github/workflows` folder to see how the application is deployed on dev and prod servers.

## Features

- modern
  - `argon2` hash algorithm
  - JWT tokens (token-based authentication)
  - JWKS
  - [dockerised](https://hub.docker.com/r/rshelekhov/grpc-sso)
- developer friendly
  - local instance for testing and debug
  - postman collection with documentation
  - extendable logic
  - understandable errors and logs

## Built With

- PostgresQL as a main database
- S3 as a storage for pem files
- Mailgun as an email service
- [golang-migrate](https://github.com/golang-migrate/migrate) for the database migrations
- [sqlc](https://github.com/sqlc-dev/sqlc) as the generator type-safe code from SQL
- [viper](https://github.com/spf13/viper) as a complete configuration solution for Go applications including [12-Factor apps](https://12factor.net/#the_twelve_factors)
- [log/slog](https://pkg.go.dev/log/slog) as the centralized Syslog logger
- [ksuid](https://github.com/segmentio/ksuid) as the unique identifier
- [golangci-lint](https://github.com/golangci/golangci-lint) as a Go linters runner
