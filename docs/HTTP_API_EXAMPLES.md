# SSO HTTP API Examples

This document provides examples of how to interact with the SSO service using HTTP/REST endpoints via the grpc-gateway.

## Base URL

- **Local Development**: `http://localhost:8080`
- **Docker**: `http://localhost:8080`

## Authentication

Most endpoints require a JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

**Important:** The "Bearer " prefix is **required** for HTTP/REST API requests per RFC 6750 standard.

Some endpoints require a Client ID in the `X-Client-Id` header:

```
X-Client-Id: <client_id>
```

## Enumerations

### Platform

The `platform` field in `user_device_data` must be one of:

- `PLATFORM_UNSPECIFIED` - Default/unspecified (not recommended for production)
- `PLATFORM_WEB` - Web browsers
- `PLATFORM_IOS` - iOS devices
- `PLATFORM_ANDROID` - Android devices

**Example usage in JSON:**
```json
{
  "user_device_data": {
    "user_agent": "Mozilla/5.0...",
    "ip": "192.168.1.100",
    "platform": "PLATFORM_WEB"
  }
}
```

---

## Authentication Service (`/v1/auth/*`)

### 1. Register User

Create a new user account.

```bash
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "confirm_password": "SecurePassword123!",
    "name": "John Doe"
  }'
```

**Response:**
```json
{
  "userId": "ksuid_generated_id",
  "message": "Verification email sent"
}
```

### 2. Verify Email

Verify user email with token from registration email. This endpoint uses GET with query parameter, so users can verify by simply clicking the link in their email.

**Email Link Example:**
```
http://localhost:8080/v1/auth/verify-email?token=verification_token_from_email
```

**cURL Example:**
```bash
curl "http://localhost:8080/v1/auth/verify-email?token=verification_token_from_email"
```

**Response:**
```json
{}
```

**Notes:**
- This is a GET endpoint - users click the link directly from email
- No authentication headers required
- Empty response body on success (HTTP 200)

### 3. Login

Authenticate user and receive access/refresh tokens.

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
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
    "expiresAt": "2025-11-16T15:30:00Z"
  }
}
```

### 4. Refresh Tokens

Get new access token using refresh token.

```bash
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
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
    "expiresAt": "2025-11-16T15:45:00Z"
  }
}
```

### 5. Get JWKS

Get JSON Web Key Set for token verification (public endpoint).

```bash
curl http://localhost:8080/v1/auth/.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### 6. Reset Password

Request password reset email. The email will contain a link to your frontend page (specified in `confirm_url`) with the reset token as a query parameter.

```bash
curl -X POST http://localhost:8080/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "email": "user@example.com",
    "confirm_url": "https://your-frontend.com/reset-password"
  }'
```

**Response:**
```json
{}
```

**Email Flow:**
1. SSO sends email with link: `https://your-frontend.com/reset-password?token=abc123`
2. User clicks link → Your frontend page opens
3. User enters new password on your form
4. Your frontend calls `/v1/auth/change-password` (see next section)

**Notes:**
- Empty response body on success (HTTP 200)
- For security, the message doesn't reveal if the email exists

### 7. Change Password

Change password using reset token from email. This is called by your frontend after user enters new password.

```bash
curl -X POST http://localhost:8080/v1/auth/change-password \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "token": "reset_token_from_email",
    "updated_password": "NewSecurePassword123!"
  }'
```

**Response:**
```json
{}
```

**Notes:**
- Empty response body on success (HTTP 200)
- Token is single-use and time-limited (typically 15 minutes)
- Password confirmation should be validated on your frontend
- If token expired, user must request a new reset link

### 8. Logout

Terminate user session.

```bash
curl -X POST http://localhost:8080/v1/auth/logout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: test-client-id" \
  -d '{
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
  "message": "Logged out successfully"
}
```

---

## User Service (`/v1/user/*`)

### 1. Get Current User

Get authenticated user's profile.

```bash
curl http://localhost:8080/v1/user \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: test-client-id"
```

**Response:**
```json
{
  "user": {
    "id": "ksuid_user_id",
    "email": "user@example.com",
    "name": "John Doe",
    "verified": false,
    "updatedAt": "2025-11-16T14:30:00Z"
  }
}
```

### 2. Get User By ID

Get any user's profile by ID (admin).

```bash
curl http://localhost:8080/v1/user/ksuid_user_id \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: test-client-id"
```

**Response:**
```json
{
  "user": {
    "id": "ksuid_user_id",
    "email": "user@example.com",
    "name": "John Doe",
    "verified": false,
    "updatedAt": "2025-11-16T14:30:00Z"
  }
}
```

### 3. Update User

Update current user's profile.

```bash
curl -X PATCH http://localhost:8080/v1/user \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "name": "Jane Doe",
    "email": "newemail@example.com",
    "currentPassword": "CurrentPassword123!",
    "newPassword": "NewPassword123!",
    "confirmPassword": "NewPassword123!"
  }'
```

**Response:**
```json
{
  "user": {
    "id": "ksuid_user_id",
    "email": "newemail@example.com",
    "name": "Jane Doe",
    "verified": true,
    "updatedAt": "2025-11-16T15:00:00Z"
  }
}
```

### 4. Delete Current User

Delete authenticated user's account.

```bash
curl -X DELETE http://localhost:8080/v1/user \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: test-client-id"
```

**Response:**
```json
{
  "message": "User deleted successfully"
}
```

### 5. Delete User By ID

Delete any user by ID (admin).

```bash
curl -X DELETE http://localhost:8080/v1/user/ksuid_user_id \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: test-client-id"
```

**Response:**
```json
{
  "message": "User deleted successfully"
}
```

### 6. Search Users

Search for users with pagination.

```bash
curl "http://localhost:8080/v1/users/search?query=john&limit=10&cursor=" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Client-Id: test-client-id"
```

**Response:**
```json
{
  "users": [
    {
      "id": "ksuid_user_id_1",
      "email": "john.doe@example.com",
      "name": "John Doe",
      "verified": true,
      "updatedAt": "2025-11-15T10:00:00Z"
    },
    {
      "id": "ksuid_user_id_2",
      "email": "john.smith@example.com",
      "name": "John Smith",
      "verified": false,
      "updatedAt": "2025-11-14T09:00:00Z"
    }
  ],
  "nextCursor": "encoded_cursor_string",
  "totalCount": 25
}
```

---

## Client Management Service (`/v1/clients/*`)

### 1. Register Client

Register a new client application.

```bash
curl -X POST http://localhost:8080/v1/clients/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "secret": "client-secret-key"
  }'
```

**Response:**
```json
{
  "clientId": "generated_client_id",
  "name": "my-app",
  "createdAt": "2025-11-16T14:30:00Z"
}
```

---

## Error Responses

All endpoints return errors in a consistent format:

```json
{
  "code": "ERROR_CODE_VALIDATION_ERROR",
  "message": "Validation failed",
  "details": {
    "email": ["Email is required"],
    "password": ["Password must be at least 8 characters"]
  }
}
```

### Common Error Codes

- `ERROR_CODE_VALIDATION_ERROR` - Invalid request format
- `ERROR_CODE_USER_NOT_FOUND` - User does not exist
- `ERROR_CODE_USER_ALREADY_EXISTS` - User with this email already exists
- `ERROR_CODE_INVALID_CREDENTIALS` - Wrong email or password
- `ERROR_CODE_SESSION_EXPIRED` - Session has expired
- `ERROR_CODE_SESSION_NOT_FOUND` - Session not found
- `ERROR_CODE_TOKEN_EXPIRED_EMAIL_RESENT` - Token expired, new email sent
- `ERROR_CODE_EMAIL_ALREADY_TAKEN` - Email already in use

---

## Testing with cURL

### Complete Authentication Flow

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!",
    "confirm_password": "Test123!",
    "name": "Test User"
  }'

# 2. Verify email (get token from email or logs)
curl "http://localhost:8080/v1/auth/verify-email?token=your_verification_token"

# 3. Login
ACCESS_TOKEN=$(curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!",
    "user_device_data": {
      "user_agent": "curl",
      "ip": "127.0.0.1",
      "platform": "PLATFORM_WEB"
    }
  }' | jq -r '.tokenData.accessToken')

echo "Access Token: $ACCESS_TOKEN"

# 4. Get user profile
curl http://localhost:8080/v1/user \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Client-Id: test-client-id"

# 5. Logout
curl -X POST http://localhost:8080/v1/auth/logout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Client-Id: test-client-id" \
  -d '{
    "user_device_data": {
      "user_agent": "curl",
      "ip": "127.0.0.1",
      "platform": "PLATFORM_WEB"
    }
  }'
```

---

## Next Steps

- For TypeScript SDK usage, see `examples/http/`
- For gRPC examples, see the gRPC client documentation
- For production deployment, ensure HTTPS is enabled
