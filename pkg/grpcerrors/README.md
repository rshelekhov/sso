# grpcerrors

Package `grpcerrors` provides utilities for extracting and handling structured error information from gRPC responses.

## Why This Package Exists

When the SSO service returns errors to clients, it uses a two-layer error approach:

1. **gRPC Status Codes** - Standard HTTP-like codes (`Unauthenticated`, `NotFound`, `InvalidArgument`, etc.)
2. **Domain Error Codes** - Business-specific error codes defined in proto files (`ERROR_CODE_INVALID_CREDENTIALS`, `ERROR_CODE_USER_NOT_FOUND`, etc.)

This package helps **client applications** (API gateways, SDKs, frontend services) to:

- Extract domain-specific error codes from gRPC errors
- Make decisions based on specific error types
- Translate SSO errors to their own domain errors
- Provide better error messages to end users

## When To Use

Use this package in **client code** that calls the SSO service:

- ✅ API Gateway translating SSO errors to REST errors
- ✅ Client SDK wrapping gRPC calls
- ✅ BFF (Backend for Frontend) services
- ✅ Integration tests validating error responses

**Don't use** this package in the SSO service itself - it's for clients only.

## Installation

```bash
go get github.com/rshelekhov/sso/pkg/grpcerrors
```

## Usage

### Basic Error Extraction

Extract all error information from a gRPC error:

```go
import (
    "context"

    authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
    commonv1 "github.com/rshelekhov/sso-protos/gen/go/api/common/v1"
    "github.com/rshelekhov/sso/pkg/grpcerrors"
)

func login(ctx context.Context, client authv1.AuthServiceClient) error {
    resp, err := client.Login(ctx, &authv1.LoginRequest{
        Email:    "user@example.com",
        Password: "wrong-password",
    })
    if err != nil {
        // Extract error information
        extracted, extractErr := grpcerrors.ExtractError(err)
        if extractErr != nil {
            // Not a gRPC error or extraction failed
            return fmt.Errorf("service error: %w", err)
        }

        // Log detailed error information
        log.Printf("gRPC Code: %s", extracted.GRPCCode)
        log.Printf("Error Code: %s", extracted.ErrorCode)
        log.Printf("Message: %s", extracted.Message)
        log.Printf("Has Details: %v", extracted.HasDetails)

        return err
    }

    // Handle successful response
    return nil
}
```

### Check Specific Error Code

Check if an error matches a specific domain error code:

```go
import (
    commonv1 "github.com/rshelekhov/sso-protos/gen/go/api/common/v1"
    "github.com/rshelekhov/sso/pkg/grpcerrors"
)

func handleLoginError(err error) string {
    if grpcerrors.IsErrorCode(err, commonv1.ErrorCode_ERROR_CODE_INVALID_CREDENTIALS) {
        return "Invalid email or password"
    }

    if grpcerrors.IsErrorCode(err, commonv1.ErrorCode_ERROR_CODE_USER_NOT_FOUND) {
        return "User not found"
    }

    if grpcerrors.IsErrorCode(err, commonv1.ErrorCode_ERROR_CODE_SESSION_EXPIRED) {
        return "Your session has expired. Please log in again."
    }

    return "An error occurred. Please try again."
}
```

### Get Error Code Only

Extract just the error code without other information:

```go
import (
    commonv1 "github.com/rshelekhov/sso-protos/gen/go/api/common/v1"
    "github.com/rshelekhov/sso/pkg/grpcerrors"
)

func getErrorCode(err error) commonv1.ErrorCode {
    code, err := grpcerrors.GetErrorCode(err)
    if err != nil {
        // Error has no details or is not a gRPC error
        return commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED
    }
    return code
}
```

### Check gRPC Status Code

Check standard gRPC status codes:

```go
import (
    "github.com/rshelekhov/sso/pkg/grpcerrors"
    "google.golang.org/grpc/codes"
)

func isRetryable(err error) bool {
    // Retry on transient errors
    return grpcerrors.IsGRPCCode(err, codes.Unavailable) ||
           grpcerrors.IsGRPCCode(err, codes.Internal) ||
           grpcerrors.IsGRPCCode(err, codes.DeadlineExceeded)
}
```

## Real-World Example: API Gateway

Here's how an API gateway translates SSO errors to its own domain errors:

```go
package gateway

import (
    "context"
    "errors"

    authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
    commonv1 "github.com/rshelekhov/sso-protos/gen/go/api/common/v1"
    "github.com/rshelekhov/sso/pkg/grpcerrors"
    "google.golang.org/grpc/codes"
)

// Gateway domain errors
var (
    ErrBadCredentials = errors.New("invalid email or password")
    ErrSessionExpired = errors.New("session expired, please login again")
    ErrUserExists     = errors.New("user already exists")
    ErrInvalidRequest = errors.New("invalid request parameters")
    ErrNotFound       = errors.New("resource not found")
    ErrServiceFailure = errors.New("service temporarily unavailable")
)

type AuthService struct {
    ssoClient authv1.AuthServiceClient
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*LoginResult, error) {
    req := &authv1.LoginRequest{
        Email:    email,
        Password: password,
    }

    resp, err := s.ssoClient.Login(ctx, req)
    if err != nil {
        // Translate SSO error to gateway error
        return nil, s.translateError(err)
    }

    return &LoginResult{
        UserID:       resp.UserId,
        AccessToken:  resp.TokenData.AccessToken,
        RefreshToken: resp.TokenData.RefreshToken,
    }, nil
}

func (s *AuthService) translateError(err error) error {
    extracted, extractErr := grpcerrors.ExtractError(err)
    if extractErr != nil {
        return ErrServiceFailure
    }

    // Try to match specific error codes first
    if extracted.HasDetails {
        switch extracted.ErrorCode {
        case commonv1.ErrorCode_ERROR_CODE_INVALID_CREDENTIALS:
            return ErrBadCredentials

        case commonv1.ErrorCode_ERROR_CODE_SESSION_EXPIRED,
             commonv1.ErrorCode_ERROR_CODE_SESSION_NOT_FOUND:
            return ErrSessionExpired

        case commonv1.ErrorCode_ERROR_CODE_USER_ALREADY_EXISTS,
             commonv1.ErrorCode_ERROR_CODE_EMAIL_ALREADY_TAKEN:
            return ErrUserExists

        case commonv1.ErrorCode_ERROR_CODE_VALIDATION_ERROR,
             commonv1.ErrorCode_ERROR_CODE_PASSWORDS_DO_NOT_MATCH:
            return ErrInvalidRequest

        case commonv1.ErrorCode_ERROR_CODE_USER_NOT_FOUND:
            return ErrNotFound
        }
    }

    // Fallback to gRPC status code
    switch extracted.GRPCCode {
    case codes.Unauthenticated:
        return ErrBadCredentials
    case codes.NotFound:
        return ErrNotFound
    case codes.AlreadyExists:
        return ErrUserExists
    case codes.InvalidArgument:
        return ErrInvalidRequest
    case codes.Internal, codes.Unavailable:
        return ErrServiceFailure
    default:
        return ErrServiceFailure
    }
}
```

## Error Handling Strategy

### Two-Level Matching

Always try to match errors in this order:

1. **Domain error code** (most specific) - `extracted.ErrorCode`
2. **gRPC status code** (fallback) - `extracted.GRPCCode`

```go
func handleError(err error) {
    extracted, _ := grpcerrors.ExtractError(err)

    // Level 1: Check specific domain error codes
    if extracted.HasDetails {
        switch extracted.ErrorCode {
        case commonv1.ErrorCode_ERROR_CODE_INVALID_CREDENTIALS:
            // Handle specific case
            return
        }
    }

    // Level 2: Fallback to gRPC code
    switch extracted.GRPCCode {
    case codes.Unauthenticated:
        // Handle general authentication failure
        return
    }
}
```

### Handle Missing Details

Not all errors have details attached (e.g., internal errors):

```go
extracted, err := grpcerrors.ExtractError(err)
if err != nil {
    // Not a gRPC error at all
    return handleNonGRPCError(err)
}

if !extracted.HasDetails {
    // gRPC error without domain details
    // Use only GRPCCode for decision making
    return handleByGRPCCode(extracted.GRPCCode)
}

// Full details available
return handleByErrorCode(extracted.ErrorCode)
```

## API Reference

### ExtractError

```go
func ExtractError(err error) (*ExtractedError, error)
```

Extracts all error information from a gRPC error.

**Returns:**

- `*ExtractedError` - Extracted error information
- `error` - `ErrNotGRPCError` if the error is not a gRPC error, nil otherwise

### GetErrorCode

```go
func GetErrorCode(err error) (commonv1.ErrorCode, error)
```

Extracts only the domain error code from a gRPC error.

**Returns:**

- `commonv1.ErrorCode` - The error code, or `ERROR_CODE_UNSPECIFIED` on failure
- `error` - `ErrNotGRPCError` if not a gRPC error, `ErrNoErrorDetails` if no details attached

### IsErrorCode

```go
func IsErrorCode(err error, code commonv1.ErrorCode) bool
```

Checks if the error matches a specific domain error code.

**Returns:**

- `bool` - true if the error matches the specified code

### IsGRPCCode

```go
func IsGRPCCode(err error, code codes.Code) bool
```

Checks if the error matches a specific gRPC status code.

**Returns:**

- `bool` - true if the error matches the specified gRPC code

## Error Codes Reference

- [sso-protos Error Definitions](https://github.com/rshelekhov/sso-protos/blob/main/api/common/v1/errors.proto) - Proto definitions of error codes
