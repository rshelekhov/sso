# SSO Integration Guide

This guide explains how to integrate your application with the SSO service.

## Table of Contents

- [Overview](#overview)
- [Integration Methods](#integration-methods)
  - [HTTP/REST API](#httprest-api)
  - [gRPC API](#grpc-api)
- [HTTP Authentication Flow](#http-authentication-flow)
- [gRPC Authentication Flow](#grpc-authentication-flow)
- [Email Verification](#email-verification)
- [Password Reset](#password-reset)
- [Session Management](#session-management)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Overview

The SSO service provides authentication and user management via both HTTP/REST and gRPC APIs. Choose the integration method that best fits your application architecture.

### Architecture

```
User Browser / Client App
    ↓
Your Application
    ↓ (HTTP/REST or gRPC)
SSO Service
    ↓
Database / Email Service
```

## Integration Methods

The SSO service supports two integration methods:

### HTTP/REST API

**Best for:**
- Web applications (JavaScript/TypeScript frontends)
- Mobile apps (iOS, Android)
- Serverless functions
- Quick prototyping
- When you want a simple HTTP-based integration

**Endpoints:** `http://localhost:8080` (default)

**Features:**
- RESTful JSON API via grpc-gateway
- Standard HTTP methods (GET, POST, PATCH, DELETE)
- Bearer token authentication (requires "Bearer " prefix per RFC 6750)
- Automatic camelCase field conversion

**Example:**
```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: your-client-id" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "user_device_data": {
      "user_agent": "Mozilla/5.0...",
      "ip": "192.168.1.100",
      "platform": "PLATFORM_WEB"
    }
  }'
```

See [HTTP_API_EXAMPLES.md](./HTTP_API_EXAMPLES.md) for complete HTTP API documentation.

### gRPC API

**Best for:**
- Backend microservices
- High-performance applications
- Strong typing requirements
- Go/Java/Python backend services

**Endpoints:** `localhost:44044` (default gRPC port)

**Features:**
- Protocol Buffers for efficient serialization
- Strong typing via generated code
- Streaming support
- Lower latency

**Example:**
```go
import authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"

resp, err := ssoClient.Login(ctx, &authv1.LoginRequest{
    Email:    "user@example.com",
    Password: "password123",
    UserDeviceData: &authv1.UserDeviceData{
        UserAgent: "MyApp/1.0",
        Ip:        "192.168.1.100",
        Platform:  authv1.Platform_PLATFORM_WEB,
    },
})
```

## HTTP Authentication Flow

### User Registration (HTTP)

**Step 1: Register via HTTP POST**

```bash
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: your-client-id" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "confirm_password": "SecurePassword123!",
    "name": "John Doe",
    "verification_url": "https://your-app.com/verify-email"
  }'
```

**Step 2: Response**

```json
{
  "userId": "2abc3Def4ghI5jkl6Mno7pQr",
  "message": "Verification email sent",
  "tokenData": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresAt": "2025-11-17T15:30:00Z"
  }
}
```

**Step 3: Login**

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: your-client-id" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "user_device_data": {
      "user_agent": "Mozilla/5.0...",
      "ip": "192.168.1.100",
      "platform": "PLATFORM_WEB"
    }
  }'
```

**Response:**
```json
{
  "tokenData": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresAt": "2025-11-17T15:30:00Z"
  }
}
```

**Step 4: Access Protected Resources**

```bash
curl http://localhost:8080/v1/user \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: your-client-id"
```

**Note:** The Authorization header follows RFC 6750 and requires the "Bearer " prefix.

## gRPC Authentication Flow

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

### Implementation Options

You have two options for handling email verification:

#### Option 1: Direct to SSO (Simplest)

Point verification URL directly to SSO's HTTP endpoint:

```go
// During registration
VerificationUrl: "https://sso.yourcompany.com/v1/auth/verify-email"

// Email will contain:
// https://sso.yourcompany.com/v1/auth/verify-email?token=abc123
```

SSO's GET endpoint handles everything automatically. No additional code needed!

#### Option 2: Through Your API Gateway (More Control)

Route through your gateway to add custom logic (logging, analytics, custom redirect):

```go
// GET /verify-email?token=XXX
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
    // 1. Extract token from query parameter
    token := r.URL.Query().Get("token")
    if token == "" {
        http.Error(w, "Missing token", http.StatusBadRequest)
        return
    }

    // 2. Call SSO via HTTP GET or gRPC
    // Option A: HTTP GET to SSO
    resp, err := http.Get(fmt.Sprintf("https://sso-internal/v1/auth/verify-email?token=%s", token))

    // Option B: gRPC call to SSO
    _, err := h.ssoClient.VerifyEmail(ctx, &authv1.VerifyEmailRequest{
        Token: token,
    })

    // 3. Handle response
    if err != nil {
        http.Error(w, "Verification failed", http.StatusBadRequest)
        return
    }

    // 4. Custom redirect to your frontend
    http.Redirect(w, r, "https://your-app.com/login?verified=true", http.StatusFound)
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

Password reset uses a frontend-based flow for security (passwords should never be in URLs).

### Step 1: Request Password Reset

```go
_, err := ssoClient.ResetPassword(ctx, &authv1.ResetPasswordRequest{
    Email:      "user@example.com",
    ConfirmUrl: "https://your-frontend.com/reset-password",  // Your frontend page!
})
```

**Important:** Point `ConfirmUrl` to your **frontend page**, not an API endpoint. Passwords must be entered on a form, not passed in URLs.

### Step 2: User Flow

```
1. SSO sends email: "https://your-frontend.com/reset-password?token=abc123"
2. User clicks → Your frontend page opens with form
3. User enters new password (+ confirmation on frontend)
4. Frontend validates password match
5. Frontend calls your API/SSO with token + password
```

### Step 3: Frontend Implementation

**Frontend page (React example):**

```jsx
function ResetPasswordPage() {
    const token = new URLSearchParams(window.location.search).get('token');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();

        // Validate on frontend
        if (password !== confirmPassword) {
            alert('Passwords do not match');
            return;
        }

        // Call your API
        await fetch('/api/change-password', {
            method: 'POST',
            body: JSON.stringify({ token, password })
        });
    };

    return (
        <form onSubmit={handleSubmit}>
            <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="New password"
            />
            <input
                type="password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                placeholder="Confirm password"
            />
            <button type="submit">Reset Password</button>
        </form>
    );
}
```

### Step 4: Backend API Implementation

**Your API endpoint:**

```go
// POST /api/change-password
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Token    string `json:"token"`
        Password string `json:"password"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    // Call SSO
    _, err := h.ssoClient.ChangePassword(ctx, &authv1.ChangePasswordRequest{
        Token:           req.Token,
        UpdatedPassword: req.Password,  // Field name: UpdatedPassword
    })

    if err != nil {
        http.Error(w, "Failed to change password", http.StatusBadRequest)
        return
    }

    w.WriteHeader(http.StatusOK)
}
```

## Session Management

### Access Token

- **Lifetime:** 15 minutes (configurable in SSO)
- **Storage:** Client-side (localStorage, memory)
- **Usage:** Include in Authorization header

**HTTP/REST:**
```bash
# Required format per RFC 6750
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**gRPC:**
```go
// Option 1: Just the token (native gRPC style)
md := metadata.Pairs("authorization", accessToken)
ctx := metadata.NewOutgoingContext(context.Background(), md)

// Option 2: With "Bearer " prefix (also supported)
md := metadata.Pairs("authorization", "Bearer "+accessToken)
ctx := metadata.NewOutgoingContext(context.Background(), md)
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

---

## FAQ: Common Integration Questions

This section addresses common questions and potential confusion points when integrating with the SSO service.

### Q1: Should I pass SSO's `/v1/auth/verify-email` URL or my own URL in `verification_url`?

**Short Answer:** It depends on your architecture needs. You have two valid patterns:

#### Pattern A: Via Your Application (Recommended for Custom UX)

**When to use:**
- You want custom success/error pages
- You need logging/analytics on email verification
- You want to redirect users after verification
- You need to trigger additional actions (welcome email, onboarding, etc.)

**Configuration:**
```go
verification_url: "https://your-app.com/verify-email"  // YOUR application's URL
```

**Architecture Diagram:**
```
┌─────────────────────────────────────────────────────────────────┐
│ Pattern A: Email Verification via Your Application              │
└─────────────────────────────────────────────────────────────────┘

1. Registration Request
   ┌──────┐                    ┌──────────┐
   │ User │──Register User──>  │ Your App │
   └──────┘  verification_url: └──────────┘
             "your-app.com/         │
             verify"                │
                                    ▼
                              ┌──────────┐
                              │   SSO    │
                              └──────────┘
                                    │
                                    │ Creates user
                                    │ Generates token
                                    ▼
2. Email Sent                 ┌──────────┐
   ┌──────┐<──Email Link───── │  Email   │
   │ User │  "your-app.com/    │ Service  │
   └──────┘  verify?token=abc" └──────────┘
      │
      │ 3. User clicks link
      ▼
   ┌──────────┐
   │ Your App │  https://your-app.com/verify?token=abc123
   └──────────┘
      │
      │ 4. Extract token from URL
      │    token := r.URL.Query().Get("token")
      │
      │ 5. Call SSO to verify
      ▼
   ┌──────────┐
   │   SSO    │──VerifyEmail(token)──> Marks email verified
   └──────────┘
      │
      │ 6. Success response
      ▼
   ┌──────────┐
   │ Your App │──7. Custom redirect──> /welcome?verified=true
   └──────────┘                         /dashboard
                                        /success-page
```

**Implementation Example:**
```go
// Your application endpoint
func (h *Handler) VerifyEmailPage(w http.ResponseWriter, r *http.Request) {
    // 1. Extract token from query parameter
    token := r.URL.Query().Get("token")
    if token == "" {
        http.Error(w, "Missing token", http.StatusBadRequest)
        return
    }

    // 2. Call SSO via gRPC
    _, err := h.ssoClient.VerifyEmail(r.Context(), &authv1.VerifyEmailRequest{
        Token: token,
    })

    if err != nil {
        // 3. Show custom error page
        log.Printf("Verification failed: %v", err)
        http.Redirect(w, r, "/verification-failed", http.StatusFound)
        return
    }

    // 4. Log successful verification (analytics)
    h.analytics.Track("email_verified", token)

    // 5. Show custom success page
    http.Redirect(w, r, "/welcome?verified=true", http.StatusFound)
}
```

**Benefits:**
- ✅ Custom success/error pages with your branding
- ✅ Analytics and tracking
- ✅ Additional logic (send welcome email, trigger onboarding)
- ✅ Full control over user experience

**Drawbacks:**
- ⚠️ More code to write
- ⚠️ Need to handle errors
- ⚠️ Your application must be publicly accessible

---

#### Pattern B: Direct to SSO (Simplest)

**When to use:**
- Quick prototyping
- You don't need custom verification pages
- SSO is publicly accessible
- You want zero implementation code

**Configuration:**
```go
verification_url: "https://sso.yourcompany.com/v1/auth/verify-email"  // SSO's PUBLIC URL
```

**Architecture Diagram:**
```
┌─────────────────────────────────────────────────────────────────┐
│ Pattern B: Email Verification Direct to SSO                     │
└─────────────────────────────────────────────────────────────────┘

1. Registration Request
   ┌──────┐                    ┌──────────┐
   │ User │──Register User──>  │ Your App │
   └──────┘  verification_url: └──────────┘
             "sso.public.com/       │
             v1/auth/                │
             verify-email"           ▼
                              ┌──────────┐
                              │   SSO    │
                              └──────────┘
                                    │
                                    │ Creates user
                                    │ Generates token
                                    ▼
2. Email Sent                 ┌──────────┐
   ┌──────┐<──Email Link───── │  Email   │
   │ User │  "sso.public.com/  │ Service  │
   └──────┘  v1/auth/verify-   └──────────┘
      │      email?token=abc"
      │
      │ 3. User clicks link
      │
      ▼
   ┌──────────┐
   │   SSO    │  https://sso.public.com/v1/auth/verify-email?token=abc
   └──────────┘
      │
      │ 4. SSO extracts token
      │    token := r.URL.Query().Get("token")
      │
      │ 5. SSO verifies token
      │    Marks email verified
      │
      │ 6. SSO returns HTTP 200 {} (empty JSON)
      │
      └──> User sees empty JSON response
           (or you configure SSO to show a page)
```

**Implementation Example:**
```go
// NO CODE NEEDED IN YOUR APP!
// Just pass SSO's public URL during registration:

registerReq := &authv1.RegisterUserRequest{
    Email:           "user@example.com",
    Password:        "password123",
    VerificationUrl: "https://sso.yourcompany.com/v1/auth/verify-email",
    // ... other fields
}
```

**Benefits:**
- ✅ Zero code needed
- ✅ SSO handles everything
- ✅ Simplest integration

**Drawbacks:**
- ⚠️ No custom success page (user sees JSON response)
- ⚠️ No analytics/tracking
- ⚠️ SSO must be publicly accessible
- ⚠️ Limited customization

---

### Q2: Common Mistakes and How to Avoid Them

#### ❌ Mistake #1: Passing Internal Service URL

**Wrong:**
```go
verification_url: "http://sso-service:44044/v1/auth/verify-email"
```

**Why it's wrong:** Users' browsers can't reach internal Docker/Kubernetes service names.

**Fix:**
```go
// Use public URL
verification_url: "https://sso.yourcompany.com/v1/auth/verify-email"
// OR your application's URL
verification_url: "https://your-app.com/verify"
```

---

#### ❌ Mistake #2: Using API Endpoint for Password Reset

**Wrong:**
```go
confirm_password_url: "https://api.your-app.com/change-password"  // API endpoint
```

**Why it's wrong:** Email links can only make GET requests. APIs expect POST with password in body. Passwords should NEVER be in URLs.

**Fix:**
```go
// Use frontend page URL
confirm_password_url: "https://your-app.com/reset-password"  // Frontend page
```

---

#### ❌ Mistake #3: Missing Domain in URL

**Wrong:**
```go
verification_url: "/v1/auth/verify-email"  // Missing domain!
```

**Why it's wrong:** SSO needs a full URL to construct email links.

**Fix:**
```go
verification_url: "https://your-app.com/verify"  // Full URL with domain
```

---

#### ❌ Mistake #4: Confusing SSO's Routes with Your URLs

**Understanding the difference:**

```
┌────────────────────────────────────────────────────────────────┐
│ SSO's Internal Routes (from proto definition)                  │
├────────────────────────────────────────────────────────────────┤
│ These are SSO's gRPC/HTTP endpoints:                           │
│   - GET  /v1/auth/verify-email                                 │
│   - POST /v1/auth/login                                        │
│   - POST /v1/auth/register                                     │
│   - POST /v1/auth/change-password                              │
│                                                                 │
│ These are for YOUR APP to call SSO (via gRPC or HTTP)         │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│ URLs You Provide to SSO (in requests)                          │
├────────────────────────────────────────────────────────────────┤
│ These are YOUR application's URLs:                             │
│   verification_url:      "https://YOUR-app.com/verify"        │
│   confirm_password_url:  "https://YOUR-app.com/reset"         │
│                                                                 │
│ SSO appends ?token=xxx and sends to users via email           │
│ Users click → YOUR app receives → YOU call SSO's endpoints    │
└────────────────────────────────────────────────────────────────┘
```

**Example showing both:**
```go
// Step 1: Your app calls SSO to register user
registerReq := &authv1.RegisterUserRequest{
    Email:           "user@example.com",
    VerificationUrl: "https://your-app.com/verify",  // ← YOUR URL (for email)
}
resp, err := ssoClient.RegisterUser(ctx, registerReq)  // ← SSO's gRPC endpoint

// Step 2: User clicks email link → Your app receives request
// GET https://your-app.com/verify?token=abc123

// Step 3: Your app extracts token and calls SSO's API
verifyReq := &authv1.VerifyEmailRequest{
    Token: "abc123",
}
_, err := ssoClient.VerifyEmail(ctx, verifyReq)  // ← SSO's gRPC endpoint
```

---

### Q3: Password Reset - Why Must It Go to Frontend, Not API?

**The Security Problem:**

Email links can only trigger GET requests from browsers. If you point `confirm_password_url` to an API endpoint:

```
❌ BAD APPROACH:
Email: "https://api.your-app.com/change-password?token=abc123&password=newpass123"

Problems:
1. Passwords exposed in URL (logged by browsers, proxies, servers)
2. Passwords visible in browser history
3. GET request can't include request body
4. URL can be accidentally shared/leaked
```

**The Correct Approach:**

```
✅ GOOD APPROACH:
Email: "https://your-app.com/reset-password?token=abc123"

Flow:
1. User clicks → Frontend page loads
2. Frontend shows password form
3. User enters password (NOT in URL)
4. Frontend POSTs to API: {token: "abc123", password: "newpass"}
5. API calls SSO.ChangePassword()
```

**Architecture Diagram:**
```
┌─────────────────────────────────────────────────────────────────┐
│ Password Reset Flow (Secure)                                    │
└─────────────────────────────────────────────────────────────────┘

1. User Requests Password Reset
   ┌──────┐                         ┌──────────┐
   │ User │──"Forgot Password"──>   │ Your App │
   └──────┘                          └──────────┘
                                           │
                                           │ ResetPassword(
                                           │   email,
                                           │   confirm_url="your-app.com/reset"
                                           │ )
                                           ▼
                                     ┌──────────┐
                                     │   SSO    │
                                     └──────────┘
                                           │
2. Email Sent                              │ Generates token
   ┌──────┐                                ▼
   │ User │<──Email Link────────     ┌──────────┐
   └──────┘  "your-app.com/reset?    │  Email   │
      │      token=abc123"            │ Service  │
      │                               └──────────┘
      │ 3. User clicks
      │    (GET request, only token in URL)
      ▼
   ┌─────────────┐
   │  Frontend   │  Loads page with form
   │    Page     │  Token: abc123 (hidden field)
   └─────────────┘
      │
      │ 4. User enters password in form
      │    Password: ••••••••
      │    Confirm:  ••••••••
      │
      │ 5. Frontend validates & submits
      │    (POST with password in BODY, not URL)
      ▼
   ┌─────────────┐
   │  Your API   │  POST /api/change-password
   └─────────────┘  Body: {
      │                token: "abc123",
      │                password: "newpass" ← In body, secure!
      │              }
      │
      │ 6. API calls SSO
      ▼
   ┌──────────┐
   │   SSO    │  ChangePassword(token, updated_password)
   └──────────┘  Verifies token, updates password
```

**Frontend Implementation Example (React):**
```jsx
function ResetPasswordPage() {
    // 1. Extract token from URL query parameter
    const token = new URLSearchParams(window.location.search).get('token');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();

        // 2. Validate on frontend
        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        // 3. POST to API (password in body, not URL!)
        try {
            const response = await fetch('/api/change-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: token,        // ← Token from URL
                    password: password   // ← Password from form (secure!)
                })
            });

            if (response.ok) {
                window.location.href = '/login?password-changed=true';
            }
        } catch (err) {
            setError('Failed to reset password');
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <h2>Reset Your Password</h2>
            <input
                type="password"
                placeholder="New password"
                value={password}
                onChange={e => setPassword(e.target.value)}
            />
            <input
                type="password"
                placeholder="Confirm password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
            />
            <button type="submit">Reset Password</button>
            {error && <div className="error">{error}</div>}
        </form>
    );
}
```

---

### Q4: Which Pattern Should I Choose?

**Decision Matrix:**

| Criteria | Pattern A (Your App) | Pattern B (Direct to SSO) |
|----------|---------------------|---------------------------|
| **Complexity** | Medium (need to write code) | Low (no code needed) |
| **Custom UX** | ✅ Full control | ❌ Limited |
| **Analytics/Tracking** | ✅ Yes | ❌ No |
| **Branding** | ✅ Your pages | ❌ Generic response |
| **Additional Logic** | ✅ Yes (welcome emails, etc.) | ❌ No |
| **SSO Accessibility** | Can be internal | Must be public |
| **Best For** | Production applications | Prototypes, simple use cases |

**Recommendation:**
- **Production Apps:** Use Pattern A (Via Your Application)
- **Prototypes/MVPs:** Use Pattern B (Direct to SSO)
- **Hybrid Approach:** Use Pattern B initially, migrate to Pattern A later

---

### Q5: Security Considerations

#### Tokens in URLs: Safe or Not?

**✅ SAFE: Verification/Reset Tokens in URLs**
```
✅ https://your-app.com/verify?token=abc123
✅ https://your-app.com/reset?token=abc123
```

**Why safe:**
- Tokens are single-use
- Tokens expire quickly (15 mins - 24 hours)
- Tokens can't be used for authentication after verification
- If leaked, attacker can only verify email or reset password once

**❌ NEVER SAFE: Passwords in URLs**
```
❌ https://your-app.com/reset?password=newpass123
```

**Why dangerous:**
- Logged everywhere (browser history, server logs, proxy logs)
- Visible in address bar
- Can be cached
- Shareable links leak credentials

---

#### Token Expiration Strategy

```
Verification Token (Email):
├─ Lifetime: 24 hours (configurable)
├─ Single-use: Yes
└─ Auto-regenerate: Yes (if expired, new email sent)

Reset Token (Password):
├─ Lifetime: 15 minutes (configurable)
├─ Single-use: Yes
└─ Auto-regenerate: Yes (if expired, new email sent)

Access Token (JWT):
├─ Lifetime: 15 minutes (configurable)
├─ Single-use: No (reusable until expiry)
└─ Refresh: Yes (via refresh token)

Refresh Token:
├─ Lifetime: 30 days (configurable)
├─ Single-use: Yes (rotates on refresh)
└─ Device-bound: Yes
```

---

### Q6: Testing Your Integration

**Quick Integration Test Checklist:**

```bash
# Test 1: Email Verification (Pattern A)
✅ Register user with verification_url="https://your-app.com/verify"
✅ Check email sent to user
✅ Extract token from email link
✅ Visit https://your-app.com/verify?token=<token>
✅ Verify your app calls SSO.VerifyEmail(token)
✅ Check custom success page displays

# Test 2: Email Verification (Pattern B)
✅ Register user with verification_url="https://sso.public.com/v1/auth/verify-email"
✅ Check email sent to user
✅ Visit link in email
✅ Verify email is marked verified in SSO

# Test 3: Password Reset
✅ Request password reset with confirm_url="https://your-app.com/reset"
✅ Check email sent
✅ Visit link → Frontend page loads
✅ Enter new password in form
✅ Submit → API calls SSO.ChangePassword()
✅ Verify password changed
✅ Test login with new password

# Test 4: Security
✅ Try using expired token → Should fail
✅ Try using token twice → Should fail (single-use)
✅ Try using invalid token → Should fail
✅ Verify passwords never appear in URLs
```

---

## Support

For issues or questions:

- Check the [Proto file](https://github.com/rshelekhov/sso-protos) for detailed API specifications
- Review the [README](../README.md) for setup instructions
- Create an issue in the repository

## Version

This guide is for SSO v0.1.0
