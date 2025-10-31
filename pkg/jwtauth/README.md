# Go JWT Authentication Library with JWKS Support

A lightweight, secure JWT authentication library for Go applications with JSON Web Key Set (JWKS) support. Features automatic key rotation, middleware for HTTP servers, and flexible token storage options.

## Features

- JWKS (JSON Web Key Set) support with automatic key rotation
- In-memory cache for JWKS to minimize requests
- Thread-safe JWKS operations
- Multiple token extraction strategies:
  - From gRPC metadata
  - From HTTP headers (Authorization Bearer token)
  - From HTTP cookies
- Middleware support for both gRPC and HTTP servers
- Context-based token management
- Flexible token handling for web and mobile applications
- Configurable token expiration
- Easy integration with existing applications
- Support for both local and remote JWKS providers

## Installation

```bash
go get github.com/rshelekhov/sso/pkg/jwtauth
```

## Usage Examples

### 1. SSO Service (Authentication Server)

```go
package main

import (
    "github.com/rshelekhov/sso/internal/adapter"
    "github.com/rshelekhov/sso/pkg/jwtauth"
    "github.com/rshelekhov/sso/internal/domain/usecase/auth"
)

func main() {
    // Initialize your auth usecase
    authUsecase := auth.NewUsecase(...)

    // Create JWKS adapter for local access
    jwksAdapter := adapter.NewJWKSAdapter(authUsecase)

    // Create JWT manager with local JWKS provider
    jwtManager := jwtauth.NewManager(jwtauth.NewLocalJWKSProvider(jwksAdapter))

    // Use in gRPC server
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(jwtManager.UnaryServerInterceptor()),
    )
}
```

### 2. Other gRPC Services

```go
package main

import (
    "github.com/rshelekhov/sso/pkg/jwtauth"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    // Create remote JWKS provider that connects to SSO service
    jwksProvider, err := jwtauth.NewRemoteJWKSProvider(
        "sso-service:50051", // SSO service address
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithBlock(),
        grpc.WithTimeout(5*time.Second),
    )
    if err != nil {
        log.Fatal("Failed to create JWKS provider:", err)
    }
    defer jwksProvider.Close()

    // Create JWT manager with remote provider and app ID
    jwtManager := jwtauth.NewManager(
        jwksProvider,
        jwtauth.WithClientID("my-service"),
    )

    // Use in your gRPC server
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(jwtManager.UnaryServerInterceptor()),
    )
}
```

### 3. API Gateway

```go
package main

import (
    "github.com/rshelekhov/sso/pkg/jwtauth"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    // Create remote JWKS provider
    jwksProvider, err := jwtauth.NewRemoteJWKSProvider(
        "sso-service:50051",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        log.Fatal("Failed to create JWKS provider:", err)
    }
    defer jwksProvider.Close()

    // Create JWT manager
    jwtManager := jwtauth.NewManager(jwksProvider)

    // Use in your HTTP server
    http.Handle("/api/", jwtManager.HTTPMiddleware)
}
```

### Extracting Claims in Downstream Services

After the middleware/interceptor verifies the token, claims are automatically added to the context. You can extract them in your handlers:

#### HTTP Handler Example

```go
func YourHandler(w http.ResponseWriter, r *http.Request) {
    // Extract claims from context
    claims := jwtauth.ClaimsFromContext(r.Context())
    if claims == nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // Access standard claims
    userID := claims.UserID
    email := claims.Email
    clientID := claims.ClientID
    deviceID := claims.DeviceID

    // Check roles
    if claims.HasRole("admin") {
        // User is an admin
    }

    // Access custom claims
    customValue := claims.GetString("custom_field")
    level := claims.GetInt64("user_level")
    verified := claims.GetBool("is_verified")

    // Use the extracted data in your business logic
    fmt.Fprintf(w, "Hello, user %s!", userID)
}
```

#### gRPC Handler Example

```go
func (s *YourService) GetProfile(ctx context.Context, req *GetProfileRequest) (*Profile, error) {
    // Extract claims from context
    claims := jwtauth.ClaimsFromContext(ctx)
    if claims == nil {
        return nil, status.Error(codes.Unauthenticated, "unauthorized")
    }

    // Access user information
    userID := claims.UserID
    email := claims.Email

    // Verify permissions
    if !claims.HasRole("user") && !claims.HasRole("admin") {
        return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
    }

    // Use claims in your business logic
    return &Profile{
        UserID: userID,
        Email:  email,
    }, nil
}
```

#### Available Claims

The `Claims` struct provides:

**Standard fields:**

- `UserID` - User identifier
- `Email` - User email
- `ClientID` - Client/application identifier
- `DeviceID` - Device identifier
- `Roles` - Array of user roles
- `Subject`, `Issuer`, `Audience`, `ExpiresAt`, `IssuedAt`, `NotBefore` - Standard JWT claims

**Methods for custom claims:**

- `GetString(key string) string` - Extract string claims
- `GetInt64(key string) int64` - Extract integer claims
- `GetBool(key string) bool` - Extract boolean claims
- `HasRole(role string) bool` - Check if user has a specific role

#### Legacy Token Verification

If you need to manually extract user ID without using claims:

```go
// Extract user ID from token
userID, err := jwtManager.ExtractUserID(ctx, clientID)
```

## Error Handling

The library provides predefined errors for common scenarios:

```go
switch err {
case jwtauth.ErrNoTokenFound:
    // Handle missing token
case jwtauth.ErrInvalidToken:
    // Handle invalid token
case jwt.ErrTokenExpired:
    // Handle expired token
default:
    // Handle general authorization failure
}
```

## Security Considerations

- Always use TLS for gRPC connections
- Set appropriate token expiration times
- Use HttpOnly cookies for web applications
- Regularly rotate your signing keys
- Use appropriate app IDs for service identification

## License

MIT License - see the LICENSE file for details

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the GitHub repository.

## Support

For questions and support, please open an issue in the GitHub repository.
