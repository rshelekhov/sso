# SSO Integration Guide

This guide explains how to integrate your application with the SSO service.

## Table of Contents

- [Overview](#overview)
- [Authentication Flow](#authentication-flow)
- [Email Verification](#email-verification)
- [Password Reset](#password-reset)
- [Session Management](#session-management)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Overview

The SSO service provides authentication and user management via gRPC. Your application (API gateway, web app, etc.) communicates with SSO to handle user registration, login, and email verification.

### Architecture

```
User Browser
    ↓
Your API Gateway (HTTP)
    ↓ (gRPC)
SSO Service
    ↓
Database / Email Service
```

## Authentication Flow

### User Registration

**Step 1: Call SSO RegisterUser**

```go
import authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"

resp, err := ssoClient.RegisterUser(ctx, &authv1.RegisterUserRequest{
    Email:           "user@example.com",
    Password:        "securePassword123",
    VerificationUrl: "https://your-app.com/verify-email",  // Your endpoint!
    UserDeviceData: &authv1.UserDeviceData{
        UserAgent: r.Header.Get("User-Agent"),
        Ip:        getClientIP(r),
    },
})
```

**Step 2: SSO Response**

```go
// User is registered but NOT verified yet
userID := resp.GetUserId()
tokens := resp.GetTokenData()
accessToken := tokens.GetAccessToken()
refreshToken := tokens.GetRefreshToken()

// Store refresh token in HTTP-only cookie
http.SetCookie(w, &http.Cookie{
    Name:     "refresh_token",
    Value:    refreshToken,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})

// Return access token to client
json.NewEncoder(w).Encode(map[string]string{
    "access_token": accessToken,
    "user_id":      userID,
})
```

**Step 3: SSO sends verification email**

SSO automatically sends an email to the user with a link like:

```
https://your-app.com/verify-email?token=a1b2c3d4e5f6...
```

## Email Verification

### URL Format

When you provide a `verification_url` during registration, SSO appends a verification token as a query parameter.

**Input:**

```
https://your-app.com/verify-email
```

**Email contains:**

```
https://your-app.com/verify-email?token=<64-char-hex-token>
```

**Token format:**

- Length: 64 characters
- Format: Hexadecimal (0-9, a-f)
- Example: `a1b2c3d4e5f6789012345678901234567890abcdefabcdef1234567890abcd`

### Implementation

**Your API Gateway endpoint:**

```go
// GET /verify-email?token=XXX
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
    // 1. Extract token from query parameter
    token := r.URL.Query().Get("token")
    if token == "" {
        http.Error(w, "Missing token", http.StatusBadRequest)
        return
    }

    // 2. Call SSO to verify
    _, err := h.ssoClient.VerifyEmail(ctx, &authv1.VerifyEmailRequest{
        Token: token,
    })

    // 3. Handle response
    if err != nil {
        // Show error page or redirect to error
        http.Error(w, "Verification failed", http.StatusBadRequest)
        return
    }

    // 4. Show success page or redirect
    http.Redirect(w, r, "/login?verified=true", http.StatusFound)
}
```

### Edge Cases

**Token expired:**

```go
if err != nil {
    if status.Code(err) == codes.InvalidArgument {
        // SSO automatically sends a new verification email
        // Show message: "Token expired. We've sent you a new email."
    }
}
```

**Token already used:**

```go
if status.Code(err) == codes.AlreadyExists {
    // User already verified
    http.Redirect(w, r, "/login", http.StatusFound)
}
```

### Complete Flow Diagram

```
1. User clicks "Register"
        ↓
2. Your Gateway → SSO.RegisterUser(verification_url="https://your-app.com/verify")
        ↓
3. SSO creates user (unverified)
        ↓
4. SSO sends email: "Click https://your-app.com/verify?token=abc123..."
        ↓
5. User clicks link → Your Gateway /verify?token=abc123
        ↓
6. Your Gateway → SSO.VerifyEmail(token="abc123")
        ↓
7. SSO marks user as verified
        ↓
8. Your Gateway shows "Email verified! Please login"
```

## Password Reset

Similar flow to email verification.

### Step 1: Request Password Reset

```go
_, err := ssoClient.ResetPassword(ctx, &authv1.ResetPasswordRequest{
    Email:      "user@example.com",
    ConfirmUrl: "https://your-app.com/reset-password",  // Your endpoint!
})
```

### Step 2: Handle Reset Link

Email contains: `https://your-app.com/reset-password?token=<64-char-hex>`

```go
// GET /reset-password?token=XXX
func (h *Handler) ShowResetPasswordForm(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")

    // Show form with token embedded
    tmpl.Execute(w, map[string]string{
        "token": token,
    })
}

// POST /reset-password
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    newPassword := r.FormValue("password")

    _, err := h.ssoClient.ChangePassword(ctx, &authv1.ChangePasswordRequest{
        Token:       token,
        NewPassword: newPassword,
    })

    if err != nil {
        // Handle error
        return
    }

    // Redirect to login
    http.Redirect(w, r, "/login?password_changed=true", http.StatusFound)
}
```

## Session Management

### Access Token

- **Lifetime:** 15 minutes (configurable in SSO)
- **Storage:** Client-side (localStorage, memory)
- **Usage:** Include in Authorization header

```go
req.Header.Set("Authorization", "Bearer "+accessToken)
```

### Refresh Token

- **Lifetime:** 30 days (configurable in SSO)
- **Storage:** HTTP-only cookie (secure)
- **Usage:** Automatically sent with requests

```go
// Token refresh endpoint
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
    // Get refresh token from cookie
    cookie, err := r.Cookie("refresh_token")
    if err != nil {
        http.Error(w, "No refresh token", http.StatusUnauthorized)
        return
    }

    // Call SSO
    resp, err := h.ssoClient.Refresh(ctx, &authv1.RefreshRequest{
        RefreshToken: cookie.Value,
        UserDeviceData: &authv1.UserDeviceData{
            UserAgent: r.Header.Get("User-Agent"),
            Ip:        getClientIP(r),
        },
    })

    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Return new access token
    json.NewEncoder(w).Encode(map[string]string{
        "access_token": resp.GetTokenData().GetAccessToken(),
    })
}
```

## Error Handling

### Common gRPC Status Codes

| Code               | Meaning             | Action                |
| ------------------ | ------------------- | --------------------- |
| `OK`               | Success             | Continue              |
| `InvalidArgument`  | Bad request data    | Show error to user    |
| `Unauthenticated`  | Invalid credentials | Show login error      |
| `AlreadyExists`    | User already exists | Show "email taken"    |
| `NotFound`         | User not found      | Show "user not found" |
| `PermissionDenied` | No access           | Redirect to login     |

### Example Error Handler

```go
func handleGRPCError(err error) (int, string) {
    st := status.Convert(err)

    switch st.Code() {
    case codes.InvalidArgument:
        return http.StatusBadRequest, st.Message()
    case codes.Unauthenticated:
        return http.StatusUnauthorized, "Invalid credentials"
    case codes.AlreadyExists:
        return http.StatusConflict, "User already exists"
    case codes.NotFound:
        return http.StatusNotFound, "User not found"
    case codes.PermissionDenied:
        return http.StatusForbidden, "Access denied"
    default:
        return http.StatusInternalServerError, "Internal server error"
    }
}
```

## Best Practices

### Security

1. **Always use HTTPS** for your verification URLs
2. **Store refresh tokens in HTTP-only cookies** (never in localStorage)
3. **Validate tokens on every request**
4. **Set proper CORS policies**
5. **Use CSRF protection** for state-changing operations

### URL Configuration

```go
// ✅ Good - Clean base URLs
verification_url: "https://your-app.com/verify-email"
confirm_url:      "https://your-app.com/reset-password"

// ❌ Bad - Don't include the token yourself
verification_url: "https://your-app.com/verify-email?token="  // Wrong!

// ✅ Good - URLs with existing query params work fine
verification_url: "https://your-app.com/verify?source=email&lang=en"
// Result: https://your-app.com/verify?source=email&lang=en&token=abc123
```

### Token Handling

```go
// ✅ Extract token from query parameter
token := r.URL.Query().Get("token")

// ✅ Validate token exists
if token == "" || len(token) != 64 {
    return errors.New("invalid token format")
}

// ✅ Send to SSO immediately
// Don't store or cache verification tokens
```

### User Experience

1. **Show loading states** during SSO calls
2. **Provide clear error messages**
3. **Redirect to appropriate pages** after verification
4. **Handle token expiration gracefully**
5. **Send new verification emails** if user didn't receive first one

### Performance

1. **Reuse gRPC connections** (connection pooling)
2. **Set appropriate timeouts** (default: 30s)
3. **Cache user data** after successful verification
4. **Use refresh tokens** instead of re-authenticating

### Monitoring

1. **Log all SSO interactions** with request IDs
2. **Track verification rates** (how many users verify emails)
3. **Monitor token expiration errors**
4. **Alert on high error rates**

## Example: Complete Registration Flow

```go
type Handler struct {
    ssoClient authv1.AuthServiceClient
}

// Registration endpoint
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
        Name     string `json:"name"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Call SSO with YOUR verification URL
    resp, err := h.ssoClient.RegisterUser(r.Context(), &authv1.RegisterUserRequest{
        Email:    req.Email,
        Password: req.Password,
        Name:     req.Name,
        VerificationUrl: "https://your-app.com/verify-email",
        UserDeviceData: &authv1.UserDeviceData{
            UserAgent: r.Header.Get("User-Agent"),
            Ip:        getClientIP(r),
        },
    })

    if err != nil {
        statusCode, msg := handleGRPCError(err)
        http.Error(w, msg, statusCode)
        return
    }

    // Set refresh token cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    resp.GetTokenData().GetRefreshToken(),
        HttpOnly: true,
        Secure:   true,
        Path:     "/",
        MaxAge:   30 * 24 * 60 * 60, // 30 days
        SameSite: http.SameSiteStrictMode,
    })

    // Return response
    json.NewEncoder(w).Encode(map[string]interface{}{
        "user_id":      resp.GetUserId(),
        "access_token": resp.GetTokenData().GetAccessToken(),
        "message":      "Registration successful. Please check your email.",
    })
}

// Verification endpoint
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    if token == "" {
        http.Error(w, "Missing token", http.StatusBadRequest)
        return
    }

    _, err := h.ssoClient.VerifyEmail(r.Context(), &authv1.VerifyEmailRequest{
        Token: token,
    })

    if err != nil {
        // Show error page
        tmpl.Execute(w, map[string]string{
            "error": "Verification failed. Please try again.",
        })
        return
    }

    // Show success page
    tmpl.Execute(w, map[string]string{
        "message": "Email verified successfully! You can now login.",
    })
}

func getClientIP(r *http.Request) string {
    // Check X-Forwarded-For header first (if behind proxy)
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        return strings.Split(xff, ",")[0]
    }

    // Check X-Real-IP
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }

    // Fallback to RemoteAddr
    ip, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ip
}
```

## Support

For issues or questions:

- Check the [Proto file](https://github.com/rshelekhov/sso-protos) for detailed API specifications
- Review the [README](../README.md) for setup instructions
- Create an issue in the repository

## Version

This guide is for SSO v0.1.0
