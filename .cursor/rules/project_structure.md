---
description: 
globs: 
alwaysApply: false
---
# Cursor Rules for Golang Backend Project

## Go General Guidelines

### Basic Principles

- Use English for all code and documentation.
- Always specify the type of each variable and function (parameters and return value).
- Avoid using `interface{}` unless absolutely necessary.
- Define appropriate structs and interfaces.
- Use GoDoc comments for public functions, methods, and types.
- Maintain consistent spacing and formatting using `gofmt`.
- One export per file where possible.

### Nomenclature

- Use PascalCase for exported functions, types, and structs.
- Use camelCase for variables, functions, and methods.
- Use kebab-case for file and directory names.
- Use UPPERCASE for environment variables.
- Avoid magic numbers; define constants using `const`.
- Prefix boolean variables with verbs: `is`, `has`, `can`, etc.
- Use full words instead of abbreviations, except for standard ones like `API`, `URL`, etc.
- Common abbreviations:
  - `ctx` for context
  - `req`, `resp` for request and response
  - `err` for errors

### Functions

- Keep functions short and focused (preferably < 20 lines).
- Name functions with a verb and an object.
- Boolean-returning functions: `IsX`, `HasX`, `CanX`, etc.
- Procedures: `ExecuteX`, `SaveX`, `ProcessX`, etc.
- Reduce nested blocks by using early returns and helper functions.
- Prefer higher-order functions (`map`, `filter`) over loops when applicable.
- Use default values instead of checking for nil.
- Reduce parameter count using structs for inputs and outputs.
- Maintain a single level of abstraction per function.

### Data

- Avoid excessive use of primitive types; encapsulate data in structs.
- Use immutability where possible.
- Use `const` for unchanging literals.
- Use pointers where mutability is required.
- Avoid validating data in functions; use dedicated validator functions or middleware.

### Structs and Interfaces

- Follow SOLID principles.
- Favor composition over inheritance.
- Use interfaces to define contracts, but avoid unnecessary abstraction.
- Keep structs small and focused:
  - Fewer than 10 fields where possible.
  - Limit the number of exported methods.
- Use method receivers (`func (s *Struct) Method()`) when mutation is required.

### Error Handling

- Use Go's error handling idioms (`if err != nil`)
- Define custom errors in `errors.go` within each package
- Use error wrapping to maintain context
- Log errors at the appropriate level
- Return errors to the caller when they should handle the failure
- Panic only for truly unrecoverable situations

### Testing

- Place tests in the same directory as the code they test
- Use `testing` package for unit tests.
- Follow the Arrange-Act-Assert pattern.
- Use table-driven tests where applicable.
- Name test variables descriptively (`inputX`, `mockX`, `actualX`, `expectedX`).
- Write unit tests for each exported function.
- Mock dependencies using interfaces where necessary.
- Write integration tests for HTTP handlers and services.
- Use `httptest` package for API testing.
- Use `testify/require` for assertions
- Test files should follow the pattern:
  1. Test setup/fixtures
  2. Helper functions
  3. Test cases
  4. Actual tests

### Documentation

- Every exported function must have a GoDoc comment
- Include examples in documentation for complex functions
- Document expected errors and edge cases
- Keep README.md up to date with:
  - Project overview
  - Setup instructions
  - Configuration options
  - API documentation

### Dependencies

- Keep external dependencies minimal
- Vendor dependencies using go modules

### Security

- Never store sensitive data in plain text
- Use environment variables for configuration
- Implement proper authentication checks
- Validate all user input
- Use prepared statements for database queries
- Implement proper CORS policies

## Application Description

This is an authentication system written using Golang

The application provides a comprehensive authentication and identity management solution with the following features:

### Core Authentication Features
- User login and registration
- Password management (reset, change)
- Multiple authentication methods:
  - Password-based login
  - Magic link login (SMS/email) (not implemented yet)
  - Passkey support (not implemented yet)
  - OTP login using TOTP authentication (not implemented yet)
- User profile management

### Multi-tenancy Support
- Create and manage multiple applications
- Role-based access control (not implemented yet)

### Authentication Flows
- Built-in login app: Redirect-based flow with SPA hosted application
- API-based: Direct HTTP requests or SDK integration with client applications

## File Organization

The application follows a clean architecture approach:

### Core Modules
- `/config`: Configuration files with environment variables and application settings
- `/internal/app`: Application management and server management (gRPC and HTTP)
- `/internal/config`: Configuration management and initialization
- `/internal/controller`: gRPC controllers and HTTP handlers for handling incoming requests
- `/internal/domain/entity`: Domain models and business objects with no external dependencies
- `/internal/domain/service`: Core business logic services
  - `/internal/domain/service/appvalidator`: Service for validating applications by appID and managing application permissions
  - `/internal/domain/service/session`: Service for session management (creation, refreshing, deletion, and validation)
  - `/internal/domain/service/token`: Service for token management (JWT creation, validation, and revocation)
  - `/internal/domain/service/userdata`: Service for user data management (creation, updating, deletion, and profile management)
  - `/internal/domain/service/verification`: Service for managing verification tokens (for user confirmation after registration and password changes)
- `/internal/domain/usecase`: Application use cases implementing business logic
  - `/internal/domain/usecase/app`: Use cases for application management (registration, validation, and configuration)
  - `/internal/domain/usecase/auth`: Use cases for authentication and authorization (registration, login, logout, token refresh)
  - `/internal/domain/usecase/user`: Use cases for user management (profile updates, user deleting)
- `/internal/infrastructure/service`: Third-party service integrations (email service for now, SMS service planned for future)


### Storage Layer
- `/internal/infrastructure/storage`: Database connections and interfaces for Mongo, Postgres and Redis
  - `/internal/infrastructure/app`: Storage interfaces and implementations for application management
    - `/internal/infrastructure/app/mongo`: MongoDB implementation of app management storage interface
    - `/internal/infrastructure/app/postgres`: PostgreSQL implementation of app management storage interface
  - `/internal/infrastructure/auth`: Storage interfaces and implementations for authentication
    - `/internal/infrastructure/auth/mongo`: MongoDB implementation of auth and user data storage interfaces
    - `/internal/infrastructure/auth/postgres`: PostgreSQL implementation of auth and user data storage interfaces
  - `/internal/infrastructure/device`: Storage interfaces for device management
    - `/internal/infrastructure/device/mongo`: MongoDB implementation of device management storage interface
    - `/internal/infrastructure/device/postgres`: PostgreSQL implementation of device management storage interface
  - `/internal/infrastructure/key`: Storage interfaces for PEM keys management
    - `/internal/infrastructure/key/fs`: File system implementation for storing PEM keys
    - `/internal/infrastructure/key/s3`: AWS S3 implementation for storing PEM keys
  - `/internal/infrastructure/mongo/common`: Shared MongoDB collections and utility functions
  - `/internal/infrastructure/session`: Storage interfaces for session management
    - `/internal/infrastructure/session/redis`: Redis implementation of session management storage interface
  - `/internal/infrastructure/transaction`: Transaction management interfaces and implementations
  - `/internal/infrastructure/user`: Storage interfaces for user management
    - `/internal/infrastructure/user/mongo`: MongoDB implementation of user management storage interfaces
    - `/internal/infrastructure/user/postgres`: PostgreSQL implementation of user management storage interfaces
  - `/internal/infrastructure/verification`: Storage interfaces for verification token management
    - `/internal/infrastructure/verification/mongo`: MongoDB implementation of verification token storage interface
    - `/internal/infrastructure/verification/postgres`: PostgreSQL implementation of verification token storage interface
- `/migrations`: SQL migration files for PostgreSQL database schema management


### Common
- `/internal/lib/e`: Helper functions for standardized error handling and logging
- `/internal/lib/interceptor`: gRPC interceptors for request processing
  - `/internal/lib/interceptor/appid`: Interceptor for extracting and validating appID from requests
  - `/internal/lib/interceptor/auth`: Interceptor for user authentication and authorization
- `/internal/lib/logger`: Logging system implementation
  - `/internal/lib/logger/handler/slogdiscard`: Null logger implementation for unit tests
  - `/internal/lib/logger/handler/slogpretty`: Pretty formatter for log output
- `/internal/lib/midleware/logger`: HTTP middleware for request logging
- `/pkg/middleware`: Abstract middleware interfaces and implementations
  - `/pkg/middleware/appid`: AppID management in request context
  - `/pkg/middleware/requestID`: Request ID tracking and management
- `/pkg/service/mail`: Email service interfaces and implementations
  - `/pkg/service/mail/mailgun`: Mailgun email service integration
  - `/pkg/service/mail/mocks`: Mock email service for testing
- `/pkg/storage`: Storage client implementations
  - `/pkg/storage/mongo`: MongoDB client and connection management
  - `/pkg/storage/postgres`: PostgreSQL client and connection management
  - `/pkg/storage/redis`: Redis client and connection management
  - `/pkg/storage/s3`: AWS S3 client and connection management

### Static Content
- `/static/email_templates`: HTML email templates for user communications

### CMD
- `/cmd/migrate`: CLI tool for database schema migrations
- `/cmd/register_app`: CLI tool for registering new applications in the SSO system
- `cmd/sso`: Main application entry point and server initialization

### Other
- `/api_tests`: Integration tests using real HTTP/gRPC requests to the SSO application

## Development Workflow

When implementing new features or making changes:

1. Start with defining or updating the models in `/internal/domain/entity`
2. Implement storage layer changes in the appropriate storage package
3. Add business logic in the domain layer (in usecase or domain services)
4. Create gRPC controller
5. Add appropriate tests at all levels

## Best Practices

- Keep the dependency graph clean - lower layers should not depend on higher layers
- Follow the Go guidelines strictly for consistent, maintainable code
- Ensure proper error handling throughout the codebase
- Write comprehensive tests for all components
- Use dependency injection for testability
- Keep the models package dependency-free
