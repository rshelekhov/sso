# JWT Claims Extraction

## Overview

The `jwtauth` package automatically extracts and parses JWT claims when validating tokens. Both the token string and parsed claims are stored in the context:

- **Claims** (`ClaimsFromContext`) - Use this for business logic (user_id, email, roles, etc.)
- **Token string** (`TokenFromContext`) - Use this for forwarding to other services or token-specific operations

**Most handlers only need Claims!** The token string is primarily for API gateways and special cases.

## Quick Usage

### HTTP Handler

```go
func YourHandler(w http.ResponseWriter, r *http.Request) {
    claims := jwtauth.ClaimsFromContext(r.Context())
    if claims == nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    userID := claims.UserID
    email := claims.Email

    // Use claims in your business logic...
}
```

### gRPC Handler

```go
func (s *Service) YourMethod(ctx context.Context, req *Request) (*Response, error) {
    claims := jwtauth.ClaimsFromContext(ctx)
    if claims == nil {
        return nil, status.Error(codes.Unauthenticated, "unauthorized")
    }

    userID := claims.UserID
    // Use claims...
}
```

## Available Claims

### Standard Fields

```go
claims.UserID    // User identifier
claims.Email     // User email
claims.ClientID  // Client/app identifier
claims.DeviceID  // Device identifier
claims.Roles     // []string - user roles (can be nil/empty)

// Standard JWT claims
claims.Subject
claims.Issuer
claims.Audience
claims.ExpiresAt
claims.IssuedAt
claims.NotBefore
```

### Custom Claims

```go
// Extract custom claims by key
department := claims.GetString("department")
level := claims.GetInt64("user_level")
verified := claims.GetBool("is_verified")
```

### Role Handling

The package supports flexible role handling:

#### Standard "roles" field

```go
// If token has "roles": ["admin", "user"]
if claims.HasRole("admin") {
    // User is admin
}
```

#### No roles (your SSO case)

```go
// If token has no "roles" field
claims.Roles // nil or empty []string
claims.HasRole("admin") // false - safe, no panic
```

#### Custom role field names

```go
// If client uses "permissions" instead of "roles"
// Token: {"permissions": ["read", "write"]}
permissions := claims.GetRolesFromExtra("permissions")
// Returns: []string{"read", "write"}

// Or "scopes"
scopes := claims.GetRolesFromExtra("scopes")
```

## Key Features

1. **Performance**: Token parsed only once in middleware
2. **Type Safety**: No manual type assertions needed
3. **Flexibility**: Works with or without roles
4. **Compatibility**: Different clients can use different claim structures
5. **Safety**: All methods handle nil/empty values gracefully

## Example Scenarios

### Scenario 1: Your SSO (No Roles)

```go
// Token payload from your SSO:
{
  "user_id": "123",
  "email": "user@example.com"
  // No "roles" field
}

// In handler:
claims := jwtauth.ClaimsFromContext(ctx)
userID := claims.UserID          // "123"
claims.HasRole("admin")          // false (safe)
len(claims.Roles)                // 0
```

### Scenario 2: Client with Standard Roles

```go
// Token payload from client with roles:
{
  "user_id": "456",
  "email": "admin@example.com",
  "roles": ["admin", "moderator"]
}

// In handler:
claims := jwtauth.ClaimsFromContext(ctx)
claims.HasRole("admin")          // true
claims.Roles                     // []string{"admin", "moderator"}
```

### Scenario 3: Client with Custom Role Field

```go
// Token payload with "permissions":
{
  "user_id": "789",
  "permissions": ["api:read", "api:write"]
}

// In handler:
claims := jwtauth.ClaimsFromContext(ctx)
claims.Roles                     // nil (no "roles" field)
permissions := claims.GetRolesFromExtra("permissions")
// []string{"api:read", "api:write"}
```

## When to Use Token String vs Claims

### Use Claims (99% of cases)

```go
// ✅ Getting user information
claims := jwtauth.ClaimsFromContext(ctx)
userID := claims.UserID

// ✅ Authorization checks
if claims.HasRole("admin") { ... }

// ✅ Business logic
email := claims.Email
```

### Use Token String (special cases)

```go
// ✅ Forwarding to backend services
token := jwtauth.TokenFromContext(ctx)
req.Header.Set("Authorization", "Bearer "+token)

// ✅ Token revocation checks
token := jwtauth.TokenFromContext(ctx)
if revocationList.IsRevoked(token) { ... }

// ✅ Audit logging (token hash for tracking)
token := jwtauth.TokenFromContext(ctx)
log.Info("action", "token_hash", hash(token))
```
