# Go JWT Authentication Library with JWKS Support

A lightweight, secure JWT authentication library for Go applications with JSON Web Key Set (JWKS) support. Features automatic key rotation, middleware for HTTP servers, and flexible token storage options.

## Features

- JWKS (JSON Web Key Set) support with automatic key rotation
- In-memory cache for JWKS to minimize HTTP requests
- Thread-safe JWKS operations
- Multiple token extraction strategies:
- - From gRPC metadata
- - From HTTP headers (Authorization Bearer token)
- - From HTTP cookies
- Middleware support for both gRPC and HTTP servers
- Context-based token management
- Flexible token handling for web and mobile applications
- Configurable token expiration
- Easy integration with existing applications
- No external authentication service dependencies

## Installation

```bash
go get github.com/rshelekhov/sso/pkg/jwtauth
```

## Usage

### Initializing the JWT Manager

```go
package main

import (
    "github.com/rshelekhov/sso/pkg/jwtauth"
    "net/http"
)

func main() {
    // For SSO service or authentication server
    jwtManager := jwtauth.NewManager(
        "https://your-auth-server/.well-known/jwks.json"
    )

    // For client application with an optional app ID
    jwtManager := jwtauth.NewManager(
        "https://your-auth-server/.well-known/jwks.json",
        jwtauth.WithAppID("your-app-id")
    )
}
```

### Middleware for Different Protocols

#### gRPC Middleware

```go
// Use as a gRPC unary server interceptor
grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(jwtManager.UnaryServerInterceptor()),
)
```

#### HTTP Middleware

```go
// Wrap your HTTP handler with JWT verification
protectedHandler := jwtManager.HTTPMiddleware(yourHandler)
```

### Web Application Integration

```go
func (h *handler) handleLogin(w http.ResponseWriter, r *http.Request) {
    // After successful authentication, send tokens to web client
    tokenResp := &jwtauth.TokenResponse{
        AccessToken:  "generated-access-token",
        RefreshToken: "generated-refresh-token",
        Domain:      "yourdomain.com",
        Path:        "/",
        ExpiresAt:   time.Now().Add(24 * time.Hour),
        HttpOnly:    true,
    }

    h.jwtManager.SendTokensToWeb(w, tokenResp, http.StatusOK)
}
```

### Mobile Application Integration

```go
func (h *handler) handleMobileLogin(w http.ResponseWriter, r *http.Request) {
    // After successful authentication, send tokens to mobile client
    tokenResp := &jwtauth.TokenResponse{
        AccessToken:  "generated-access-token",
        RefreshToken: "generated-refresh-token",
        AdditionalFields: map[string]string{
            "user_id": "123",
            "role": "user",
        },
    }

    h.jwtManager.SendTokensToMobileApp(w, tokenResp, http.StatusOK)
}
```

### Token Response Structure

The library provides a flexible TokenResponse structure that can be used to handle various authentication scenarios:

```go
type TokenResponse struct {
    AccessToken      string            // JWT access token
    RefreshToken     string            // Refresh token for token renewal
    Domain           string            // Cookie domain (optional)
    Path             string            // Cookie path (optional)
    ExpiresAt        time.Time         // Token expiration time
    HttpOnly         bool              // HttpOnly flag for cookies
    AdditionalFields map[string]string // Additional data to be included in response
}
```

### Token Verification and User Extraction

```go
// Extract user ID from token
userID, err := jwtManager.ExtractUserID(ctx, appID)

// Verify token manually
err := jwtManager.verifyToken(appID, tokenString)
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

- Always use HTTPS for token transmission
- Set appropriate token expiration times
- Use HttpOnly cookies for web applications
- Keep your JWKS endpoint secure
- Regularly rotate your signing keys

## License

MIT License - see the LICENSE file for details

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the GitHub repository.

## Support

For questions and support, please open an issue in the GitHub repository.
