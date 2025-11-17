/**
 * Complete Authentication Flow Example
 *
 * This example demonstrates:
 * - User registration
 * - Email verification
 * - Login
 * - Getting user profile
 * - Logout
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

// Type definitions
interface RegisterRequest {
  email: string;
  password: string;
  confirm_password: string;
  name: string;
}

interface RegisterResponse {
  userId: string;
  message: string;
  tokenData?: {
    accessToken: string;
    refreshToken: string;
    expiresAt: string;
  };
}

interface LoginRequest {
  email: string;
  password: string;
  user_device_data: {
    user_agent: string;
    ip: string;
    platform: Platform;
  };
}

interface LoginResponse {
  tokenData: {
    accessToken: string;
    refreshToken: string;
    expiresAt: string;
  };
}

interface User {
  id: string;
  email: string;
  name: string;
  verified: boolean;
  updatedAt: string;
}

interface GetUserResponse {
  user: User;
}

interface APIError {
  code: string;
  message: string;
  details?: Record<string, string[]>;
}

// Helper function to make HTTP requests
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${BASE_URL}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  const data = await response.json();

  if (!response.ok) {
    const error = data as APIError;
    throw new Error(`API Error: ${error.code} - ${error.message}`);
  }

  return data as T;
}

// Main authentication flow
async function main() {
  try {
    console.log('🚀 Starting authentication flow example\n');

    // Step 1: Register a new user
    console.log('1️⃣  Registering new user...');
    const registerData: RegisterRequest = {
      email: `test${Date.now()}@example.com`,
      password: 'SecurePassword123!',
      confirm_password: 'SecurePassword123!',
      name: 'Test User',
    };

    const registerResponse = await apiRequest<RegisterResponse>('/v1/auth/register', {
      method: 'POST',
      headers: {
        'X-Client-Id': CLIENT_ID,
      },
      body: JSON.stringify(registerData),
    });

    console.log('✅ User registered:', registerResponse.userId);
    console.log('📧 Verification email sent\n');

    // Step 2: In production, you'd get the token from email
    // For this example, we'll simulate having the token
    console.log('2️⃣  Email verification step skipped (check logs for token)\n');

    // Step 3: Login
    console.log('3️⃣  Logging in...');
    const loginData: LoginRequest = {
      email: registerData.email,
      password: registerData.password,
      user_device_data: {
        user_agent: 'TypeScript Example/1.0',
        ip: '127.0.0.1',
        platform: Platform.PLATFORM_WEB,
      },
    };

    const loginResponse = await apiRequest<LoginResponse>('/v1/auth/login', {
      method: 'POST',
      headers: {
        'X-Client-Id': CLIENT_ID,
      },
      body: JSON.stringify(loginData),
    });

    console.log('✅ Login successful!');
    console.log('🔑 Access token expires:', loginResponse.tokenData.expiresAt);
    console.log('');

    // Step 4: Get user profile
    console.log('4️⃣  Fetching user profile...');
    const userResponse = await apiRequest<GetUserResponse>('/v1/user', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${loginResponse.tokenData.accessToken}`,
        'X-Client-Id': CLIENT_ID,
      },
    });

    console.log('✅ User profile retrieved:');
    console.log('   ID:', userResponse.user.id);
    console.log('   Email:', userResponse.user.email);
    console.log('   Name:', userResponse.user.name);
    console.log('');

    // Step 5: Logout
    console.log('5️⃣  Logging out...');
    await apiRequest('/v1/auth/logout', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${loginResponse.tokenData.accessToken}`,
        'X-Client-Id': CLIENT_ID,
      },
      body: JSON.stringify({
        user_device_data: {
          user_agent: 'TypeScript Example/1.0',
          ip: '127.0.0.1',
          platform: Platform.PLATFORM_WEB,
        },
      }),
    });

    console.log('✅ Logged out successfully\n');
    console.log('🎉 Authentication flow completed!');

  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

// Run the example
main();
