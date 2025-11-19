/**
 * Error Handling Example
 *
 * This example demonstrates:
 * - Custom error classes
 * - Parsing API error responses
 * - Handling different error types
 * - Validation errors with field details
 */

const BASE_URL = 'http://localhost:8080';
const CLIENT_ID = 'test-client-id';

// Platform enum (from proto definition)
enum Platform {
  PLATFORM_UNSPECIFIED = 'PLATFORM_UNSPECIFIED',
  PLATFORM_WEB = 'PLATFORM_WEB',
  PLATFORM_IOS = 'PLATFORM_IOS',
  PLATFORM_ANDROID = 'PLATFORM_ANDROID',
}

// API Error Response Type
interface APIErrorResponse {
  code: string;
  message: string;
  details?: Record<string, string[]>;
}

// Custom Error Classes
class SSOError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode?: number,
    public details?: unknown
  ) {
    super(message);
    this.name = 'SSOError';
  }
}

class ValidationError extends SSOError {
  constructor(
    message: string,
    public fields: Record<string, string[]>
  ) {
    super(message, 'VALIDATION_ERROR', 400, fields);
    this.name = 'ValidationError';
  }

  getFieldErrors(field: string): string[] {
    return this.fields[field] || [];
  }

  hasFieldError(field: string): boolean {
    return field in this.fields;
  }
}

class AuthenticationError extends SSOError {
  constructor(message: string, details?: unknown) {
    super(message, 'AUTHENTICATION_ERROR', 401, details);
    this.name = 'AuthenticationError';
  }
}

class NotFoundError extends SSOError {
  constructor(message: string, details?: unknown) {
    super(message, 'NOT_FOUND', 404, details);
    this.name = 'NotFoundError';
  }
}

class ConflictError extends SSOError {
  constructor(message: string, details?: unknown) {
    super(message, 'CONFLICT', 409, details);
    this.name = 'ConflictError';
  }
}

// Error Handler
function parseAPIError(response: Response, errorBody: APIErrorResponse): SSOError {
  const { code, message, details } = errorBody;

  // Map error codes to custom error classes
  switch (code) {
    case 'ERROR_CODE_VALIDATION_ERROR':
      return new ValidationError(message, details as Record<string, string[]>);

    case 'ERROR_CODE_INVALID_CREDENTIALS':
    case 'ERROR_CODE_SESSION_EXPIRED':
    case 'ERROR_CODE_SESSION_NOT_FOUND':
      return new AuthenticationError(message, details);

    case 'ERROR_CODE_USER_NOT_FOUND':
    case 'ERROR_CODE_VERIFICATION_TOKEN_NOT_FOUND':
      return new NotFoundError(message, details);

    case 'ERROR_CODE_USER_ALREADY_EXISTS':
    case 'ERROR_CODE_EMAIL_ALREADY_TAKEN':
    case 'ERROR_CODE_CLIENT_ALREADY_EXISTS':
      return new ConflictError(message, details);

    default:
      return new SSOError(message, code, response.status, details);
  }
}

// API Client with Error Handling
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    throw parseAPIError(response, data as APIErrorResponse);
  }

  return data as T;
}

// Examples of handling different errors
async function exampleValidationError() {
  console.log('\n1️⃣  Validation Error Example');
  console.log('   Attempting to register with invalid data...\n');

  try {
    await apiRequest('/v1/auth/register', {
      method: 'POST',
      headers: { 'X-Client-Id': CLIENT_ID },
      body: JSON.stringify({
        email: 'invalid-email',
        password: '123', // Too short
        confirm_password: '456', // Doesn't match
        name: '',
      }),
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      console.log('   ❌ Validation Error Caught:');
      console.log('   Message:', error.message);
      console.log('   Fields with errors:');

      for (const [field, errors] of Object.entries(error.fields)) {
        console.log(`     - ${field}:`, errors.join(', '));
      }

      // Check specific field
      if (error.hasFieldError('email')) {
        console.log('\n   📧 Email errors:', error.getFieldErrors('email'));
      }
    }
  }
}

async function exampleAuthenticationError() {
  console.log('\n2️⃣  Authentication Error Example');
  console.log('   Attempting to login with wrong credentials...\n');

  try {
    await apiRequest('/v1/auth/login', {
      method: 'POST',
      headers: { 'X-Client-Id': CLIENT_ID },
      body: JSON.stringify({
        email: 'user@example.com',
        password: 'wrong_password',
        user_device_data: {
          user_agent: 'TypeScript/1.0',
          ip: '127.0.0.1',
          platform: Platform.PLATFORM_WEB,
        },
      }),
    });
  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.log('   ❌ Authentication Error Caught:');
      console.log('   Code:', error.code);
      console.log('   Message:', error.message);
      console.log('   Status:', error.statusCode);
      console.log('\n   💡 User should be prompted to check credentials');
    }
  }
}

async function exampleNotFoundError() {
  console.log('\n3️⃣  Not Found Error Example');
  console.log('   Attempting to get non-existent user...\n');

  try {
    await apiRequest('/v1/user/nonexistent-id', {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer fake-token',
        'X-Client-Id': CLIENT_ID,
      },
    });
  } catch (error) {
    if (error instanceof NotFoundError) {
      console.log('   ❌ Not Found Error Caught:');
      console.log('   Message:', error.message);
      console.log('\n   💡 Show user-friendly "not found" message');
    }
  }
}

async function exampleConflictError() {
  console.log('\n4️⃣  Conflict Error Example');
  console.log('   Attempting to register duplicate email...\n');

  try {
    // First registration
    const email = `test${Date.now()}@example.com`;
    await apiRequest('/v1/auth/register', {
      method: 'POST',
      headers: { 'X-Client-Id': CLIENT_ID },
      body: JSON.stringify({
        email,
        password: 'SecurePass123!',
        confirm_password: 'SecurePass123!',
        name: 'Test User',
      }),
    });

    console.log('   ✅ First registration successful');

    // Try to register again with same email
    await apiRequest('/v1/auth/register', {
      method: 'POST',
      headers: { 'X-Client-Id': CLIENT_ID },
      body: JSON.stringify({
        email, // Same email
        password: 'SecurePass123!',
        confirm_password: 'SecurePass123!',
        name: 'Another User',
      }),
    });
  } catch (error) {
    if (error instanceof ConflictError) {
      console.log('   ❌ Conflict Error Caught:');
      console.log('   Code:', error.code);
      console.log('   Message:', error.message);
      console.log('\n   💡 Suggest user to login instead or use different email');
    }
  }
}

async function exampleGenericErrorHandling() {
  console.log('\n5️⃣  Generic Error Handling Pattern\n');

  try {
    // Some API call
    await apiRequest('/v1/user', {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer invalid-token',
        'X-Client-Id': CLIENT_ID,
      },
    });
  } catch (error) {
    // Handle errors based on type
    if (error instanceof ValidationError) {
      console.log('   📝 Handle validation errors - show field errors to user');
    } else if (error instanceof AuthenticationError) {
      console.log('   🔐 Handle auth errors - redirect to login');
    } else if (error instanceof NotFoundError) {
      console.log('   🔍 Handle not found - show 404 page');
    } else if (error instanceof ConflictError) {
      console.log('   ⚠️  Handle conflicts - suggest alternative action');
    } else if (error instanceof SSOError) {
      console.log('   ⚠️  Handle other SSO errors:', error.code);
    } else {
      console.log('   ❌ Handle unexpected errors:', error);
    }
  }
}

// Main function
async function main() {
  console.log('🚀 Error Handling Examples\n');
  console.log('This demonstrates how to handle different API errors in your SDK\n');

  await exampleValidationError();
  await exampleAuthenticationError();
  await exampleNotFoundError();
  await exampleConflictError();
  await exampleGenericErrorHandling();

  console.log('\n✅ All error handling examples completed!\n');
  console.log('💡 Key takeaways for your SDK:');
  console.log('   - Create custom error classes for different error types');
  console.log('   - Parse API error codes into specific error instances');
  console.log('   - Provide helpful methods on error objects (e.g., getFieldErrors)');
  console.log('   - Document which errors each SDK method can throw');
  console.log('   - Make errors easy to handle with instanceof checks');
}

main().catch(console.error);
