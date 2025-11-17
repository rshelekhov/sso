# TypeScript HTTP API Examples

This directory contains TypeScript examples for interacting with the SSO HTTP API.

These examples are designed to help you build a TypeScript SDK using Bun or Node.js.

## Prerequisites

```bash
# Using Bun
bun install

# Using Node.js
npm install
```

## Examples

### 1. Basic Authentication Flow
See `auth-flow.ts` for complete user registration, login, and logout flow.

```bash
bun run auth-flow.ts
# or
node auth-flow.ts
```

### 2. Token Refresh
See `token-refresh.ts` for automatic token refresh implementation.

```bash
bun run token-refresh.ts
```

### 3. User Management
See `user-management.ts` for user profile operations.

```bash
bun run user-management.ts
```

### 4. Error Handling
See `error-handling.ts` for handling API errors.

```bash
bun run error-handling.ts
```

## Building Your SDK

These examples demonstrate the patterns you'll use when building your TypeScript SDK:

1. **Type Safety** - Use TypeScript interfaces for all requests/responses
2. **Error Handling** - Custom error classes for different error types
3. **Token Management** - Automatic token refresh and storage
4. **HTTP Client** - Use native `fetch` API (works in Bun, Node 18+, browsers)

## API Base URL

- **Local**: `http://localhost:8080`
- **Docker**: `http://localhost:8080`

## Authentication

Most endpoints require:
- `Authorization: Bearer <access_token>` header
- `X-Client-Id: <client_id>` header for some endpoints

## Next Steps

Use these examples as a reference when building your full SDK with proper:
- Module structure
- Token storage strategies
- Retry logic
- Request/response interceptors
