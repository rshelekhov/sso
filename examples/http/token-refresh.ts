/**
 * Automatic Token Refresh Example
 *
 * This example demonstrates:
 * - Detecting token expiration
 * - Automatically refreshing tokens
 * - Retrying failed requests with new token
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

interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

interface RefreshResponse {
  tokenData: {
    accessToken: string;
    refreshToken: string;
    expiresAt: string;
  };
}

class TokenManager {
  private tokens: TokenPair | null = null;

  setTokens(tokens: TokenPair) {
    this.tokens = tokens;
  }

  getAccessToken(): string | null {
    return this.tokens?.accessToken ?? null;
  }

  getRefreshToken(): string | null {
    return this.tokens?.refreshToken ?? null;
  }

  isAccessTokenExpired(): boolean {
    if (!this.tokens) return true;

    // Check if token expires in the next 60 seconds
    const expiresIn = this.tokens.accessTokenExpiresAt.getTime() - Date.now();
    return expiresIn < 60000; // Less than 1 minute
  }

  isRefreshTokenExpired(): boolean {
    if (!this.tokens) return true;
    return this.tokens.refreshTokenExpiresAt.getTime() < Date.now();
  }

  async refreshTokens(deviceId: string): Promise<void> {
    if (!this.tokens?.refreshToken) {
      throw new Error('No refresh token available');
    }

    if (this.isRefreshTokenExpired()) {
      throw new Error('Refresh token expired - user must login again');
    }

    console.log('🔄 Refreshing access token...');

    const response = await fetch(`${BASE_URL}/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': CLIENT_ID,
      },
      body: JSON.stringify({
        refreshToken: this.tokens.refreshToken,
        user_device_data: {
          user_agent: 'TypeScript SDK/1.0',
          ip: '127.0.0.1',
          platform: Platform.PLATFORM_WEB,
        },
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to refresh token');
    }

    const data: RefreshResponse = await response.json();

    this.tokens = {
      accessToken: data.tokenData.accessToken,
      refreshToken: data.tokenData.refreshToken,
      accessTokenExpiresAt: new Date(data.tokenData.expiresAt),
      refreshTokenExpiresAt: new Date(data.tokenData.expiresAt),
    };

    console.log('✅ Token refreshed successfully');
  }
}

class SSOClient {
  private tokenManager = new TokenManager();
  private deviceId: string;

  constructor(deviceId: string) {
    this.deviceId = deviceId;
  }

  async login(email: string, password: string): Promise<void> {
    const response = await fetch(`${BASE_URL}/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': CLIENT_ID,
      },
      body: JSON.stringify({
        email,
        password,
        user_device_data: {
          user_agent: 'TypeScript SDK/1.0',
          ip: '127.0.0.1',
          platform: Platform.PLATFORM_WEB,
        },
      }),
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const data: RefreshResponse = await response.json();

    this.tokenManager.setTokens({
      accessToken: data.tokenData.accessToken,
      refreshToken: data.tokenData.refreshToken,
      accessTokenExpiresAt: new Date(data.tokenData.expiresAt),
      refreshTokenExpiresAt: new Date(data.tokenData.expiresAt),
    });
  }

  /**
   * Make an authenticated request with automatic token refresh
   */
  async authenticatedRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    // Check if token needs refresh before making the request
    if (this.tokenManager.isAccessTokenExpired()) {
      await this.tokenManager.refreshTokens(this.deviceId);
    }

    const accessToken = this.tokenManager.getAccessToken();
    if (!accessToken) {
      throw new Error('No access token available');
    }

    let response = await fetch(`${BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
        'X-Client-Id': CLIENT_ID,
        ...options.headers,
      },
    });

    // If we get 401, try refreshing token once and retry
    if (response.status === 401) {
      console.log('⚠️  Received 401, refreshing token and retrying...');

      await this.tokenManager.refreshTokens(this.deviceId);
      const newAccessToken = this.tokenManager.getAccessToken();

      if (!newAccessToken) {
        throw new Error('Failed to refresh token');
      }

      // Retry the request with new token
      response = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${newAccessToken}`,
          'X-Client-Id': CLIENT_ID,
          ...options.headers,
        },
      });
    }

    if (!response.ok) {
      throw new Error(`Request failed: ${response.statusText}`);
    }

    return response.json();
  }

  async getUser(): Promise<any> {
    return this.authenticatedRequest('/v1/user', { method: 'GET' });
  }

  async updateUser(name: string): Promise<any> {
    return this.authenticatedRequest('/v1/user', {
      method: 'PATCH',
      body: JSON.stringify({ name }),
    });
  }
}

// Example usage
async function main() {
  try {
    console.log('🚀 Token Refresh Example\n');

    const client = new SSOClient('typescript-refresh-example');

    // Login
    console.log('1️⃣  Logging in...');
    await client.login('user@example.com', 'password123');
    console.log('✅ Logged in\n');

    // Make requests - tokens will auto-refresh if needed
    console.log('2️⃣  Fetching user profile (auto-refresh if needed)...');
    const user = await client.getUser();
    console.log('✅ User:', user.user.email, '\n');

    // Simulate token about to expire
    console.log('3️⃣  Simulating expired token scenario...');
    console.log('   (In real SDK, this happens automatically)\n');

    // Make another request - will auto-refresh
    console.log('4️⃣  Making another request...');
    const updatedUser = await client.updateUser('Updated Name');
    console.log('✅ User updated:', updatedUser.user.name, '\n');

    console.log('🎉 Token refresh flow completed!');
    console.log('\n💡 Key takeaways for your SDK:');
    console.log('   - Check token expiration before each request');
    console.log('   - Retry 401 responses with refreshed token');
    console.log('   - Store tokens securely (memory, localStorage, etc.)');
    console.log('   - Handle refresh token expiration gracefully');

  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

main();
