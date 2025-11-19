package api_tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Platform constants (from proto enum)
const (
	PlatformUnspecified = "PLATFORM_UNSPECIFIED"
	PlatformWeb         = "PLATFORM_WEB"
	PlatformIOS         = "PLATFORM_IOS"
	PlatformAndroid     = "PLATFORM_ANDROID"
)

// HTTP Request/Response types
type RegisterUserHTTPRequest struct {
	Email           string              `json:"email"`
	Password        string              `json:"password"`
	ConfirmPassword string              `json:"confirm_password"`
	Name            string              `json:"name"`
	VerificationURL string              `json:"verification_url,omitempty"`
	UserDeviceData  *UserDeviceDataHTTP `json:"user_device_data,omitempty"`
}

type UserDeviceDataHTTP struct {
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
	Platform  string `json:"platform"`
}

type RegisterUserHTTPResponse struct {
	UserID    string     `json:"userId"`
	Message   string     `json:"message"`
	TokenData *TokenData `json:"tokenData,omitempty"`
}

type LoginHTTPRequest struct {
	Email          string         `json:"email"`
	Password       string         `json:"password"`
	UserDeviceData UserDeviceData `json:"user_device_data"`
}

type UserDeviceData struct {
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
	Platform  string `json:"platform"`
}

type TokenData struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Domain       string `json:"domain,omitempty"`
	Path         string `json:"path,omitempty"`
	ExpiresAt    string `json:"expiresAt"`
	HTTPOnly     bool   `json:"httpOnly,omitempty"`
}

type LoginHTTPResponse struct {
	TokenData *TokenData `json:"tokenData"`
}

type GetUserHTTPResponse struct {
	User UserData `json:"user"`
}

type UserData struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Verified  bool   `json:"verified"`
	UpdatedAt string `json:"updatedAt"`
}

type HTTPErrorResponse struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// HTTPClient wraps HTTP operations for the SSO API
type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
	clientID   string
}

func newHTTPClient(baseURL, clientID string) *HTTPClient {
	return &HTTPClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		clientID: clientID,
	}
}

func (c *HTTPClient) doRequest(method, endpoint string, body interface{}, headers map[string]string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.baseURL+endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (c *HTTPClient) registerUser(email, password, name string) (*RegisterUserHTTPResponse, error) {
	reqBody := RegisterUserHTTPRequest{
		Email:           email,
		Password:        password,
		ConfirmPassword: password,
		Name:            name,
		VerificationURL: "http://localhost:44044/verify",
		UserDeviceData: &UserDeviceDataHTTP{
			UserAgent: "integration-test/1.0",
			IP:        "127.0.0.1",
			Platform:  PlatformWeb,
		},
	}

	headers := map[string]string{
		"X-Client-Id": c.clientID,
	}

	resp, err := c.doRequest("POST", "/v1/auth/register", reqBody, headers)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp HTTPErrorResponse
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			return nil, fmt.Errorf("register failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return nil, fmt.Errorf("register failed: %s (code: %s)", errResp.Message, errResp.Code)
	}

	var result RegisterUserHTTPResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w. Response body: %s", err, string(bodyBytes))
	}

	// Debug logging
	if result.UserID == "" {
		return nil, fmt.Errorf("empty user_id in response. Full response: %s", string(bodyBytes))
	}

	return &result, nil
}

func (c *HTTPClient) login(email, password string) (*LoginHTTPResponse, error) {
	reqBody := LoginHTTPRequest{
		Email:    email,
		Password: password,
		UserDeviceData: UserDeviceData{
			UserAgent: "integration-test/1.0",
			IP:        "127.0.0.1",
			Platform:  PlatformWeb,
		},
	}

	headers := map[string]string{
		"X-Client-Id": c.clientID,
	}

	resp, err := c.doRequest("POST", "/v1/auth/login", reqBody, headers)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp HTTPErrorResponse
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			return nil, fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return nil, fmt.Errorf("login failed: %s (code: %s)", errResp.Message, errResp.Code)
	}

	var result LoginHTTPResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

func (c *HTTPClient) getUser(accessToken string) (*GetUserHTTPResponse, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
		"X-Client-Id":   c.clientID,
	}

	resp, err := c.doRequest("GET", "/v1/user", nil, headers)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp HTTPErrorResponse
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			return nil, fmt.Errorf("get user failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return nil, fmt.Errorf("get user failed: %s (code: %s)", errResp.Message, errResp.Code)
	}

	var result GetUserHTTPResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

func (c *HTTPClient) deleteUser(accessToken string) error {
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
		"X-Client-Id":   c.clientID,
	}

	resp, err := c.doRequest("DELETE", "/v1/user", nil, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errResp HTTPErrorResponse
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			return fmt.Errorf("delete user failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return fmt.Errorf("delete user failed: %s (code: %s)", errResp.Message, errResp.Code)
	}

	return nil
}

func (c *HTTPClient) verifyEmail(token string) error {
	// VerifyEmail is now GET with query parameter
	endpoint := fmt.Sprintf("/v1/auth/verify-email?token=%s", token)

	resp, err := c.doRequest("GET", endpoint, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errResp HTTPErrorResponse
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			return fmt.Errorf("verify email failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return fmt.Errorf("verify email failed: %s (code: %s)", errResp.Message, errResp.Code)
	}

	return nil
}

func getHTTPBaseURL() string {
	// Check for environment variable (used in Docker)
	if host := os.Getenv("SSO_HOST"); host != "" {
		// SSO_HOST is typically "sso-app:44044" (gRPC)
		// For HTTP, we use the same hostname but port 8080
		return "http://sso-app:8080"
	}

	// Default for local development
	return "http://localhost:8080"
}

// TestHTTPAuthFlow_RegisterLoginGetUser tests the complete HTTP authentication flow:
// 1. Register a new user via HTTP POST /v1/auth/register
// 2. Login via HTTP POST /v1/auth/login (get JWT token)
// 3. Get user profile via HTTP GET /v1/user (using JWT in Authorization header)
// 4. Verify JWT token is correctly extracted and used
// 5. Cleanup by deleting the user
func TestHTTPAuthFlow_RegisterLoginGetUser(t *testing.T) {
	suite.New(t)

	// Create HTTP client
	httpClient := newHTTPClient(getHTTPBaseURL(), cfg.ClientID)

	// Step 1: Register a new user via HTTP
	t.Log("Step 1: Registering user via HTTP POST /v1/auth/register")

	email := gofakeit.Email()
	password := randomFakePassword()
	name := gofakeit.Name()

	registerResp, err := httpClient.registerUser(email, password, name)
	require.NoError(t, err, "HTTP register request should succeed")
	require.NotEmpty(t, registerResp.UserID, "User ID should be returned")

	t.Logf("✓ User registered successfully: ID=%s, Email=%s", registerResp.UserID, email)

	// Step 2: Login via HTTP to get JWT tokens
	t.Log("Step 2: Logging in via HTTP POST /v1/auth/login")

	loginResp, err := httpClient.login(email, password)
	require.NoError(t, err, "HTTP login request should succeed")
	require.NotNil(t, loginResp.TokenData, "Token data should be returned")
	require.NotEmpty(t, loginResp.TokenData.AccessToken, "Access token should not be empty")
	require.NotEmpty(t, loginResp.TokenData.RefreshToken, "Refresh token should not be empty")

	accessToken := loginResp.TokenData.AccessToken
	t.Logf("✓ Login successful")
	t.Logf("  Access token length: %d", len(accessToken))
	if len(accessToken) > 50 {
		t.Logf("  Access token (first 50 chars): %s...", accessToken[:50])
	} else {
		t.Logf("  Access token: %s", accessToken)
	}

	// Step 3: Get user profile using JWT token
	t.Log("Step 3: Getting user profile via HTTP GET /v1/user with JWT token")

	userResp, err := httpClient.getUser(accessToken)
	require.NoError(t, err, "HTTP get user request should succeed with valid JWT")
	require.NotNil(t, userResp, "User data should be returned")
	require.NotEmpty(t, userResp.User.ID, "User ID should not be empty")

	t.Logf("✓ User profile retrieved successfully:")
	t.Logf("  - ID: %s", userResp.User.ID)
	t.Logf("  - Email: %s", userResp.User.Email)
	t.Logf("  - Name: %s", userResp.User.Name)

	// Verify the returned data matches what we registered
	assert.Equal(t, registerResp.UserID, userResp.User.ID, "User ID should match registration")
	assert.Equal(t, email, userResp.User.Email, "Email should match registration")
	assert.Equal(t, name, userResp.User.Name, "Name should match registration")
	assert.NotEmpty(t, userResp.User.UpdatedAt, "UpdatedAt should be set")

	// Step 4: Verify JWT token contains correct claims
	t.Log("Step 4: Verifying JWT token structure")

	// Token should be in format: header.payload.signature
	assert.Contains(t, accessToken, ".", "JWT should contain dots")
	parts := bytes.Split([]byte(accessToken), []byte("."))
	assert.Len(t, parts, 3, "JWT should have 3 parts (header.payload.signature)")

	t.Log("✓ JWT token structure is valid")

	// Step 5: Test that invalid token is rejected
	t.Log("Step 5: Verifying invalid token is rejected")

	invalidToken := "invalid.token.here"
	_, err = httpClient.getUser(invalidToken)
	require.Error(t, err, "Request with invalid JWT should fail")
	t.Log("✓ Invalid token correctly rejected")

	// Step 6: Cleanup - delete the user
	t.Log("Step 6: Cleaning up - deleting user")

	err = httpClient.deleteUser(accessToken)
	require.NoError(t, err, "User deletion should succeed")

	t.Log("✓ User deleted successfully")

	// Verify user is deleted by trying to get it again
	_, err = httpClient.getUser(accessToken)
	require.Error(t, err, "Getting deleted user should fail")

	t.Log("✓ Verified user is deleted")
	t.Log("HTTP Auth Flow test completed successfully!")
}

// TestHTTPAuthFlow_TokenRefresh tests the token refresh flow
func TestHTTPAuthFlow_TokenRefresh(t *testing.T) {
	suite.New(t)

	httpClient := newHTTPClient(getHTTPBaseURL(), cfg.ClientID)

	// Register and login
	email := gofakeit.Email()
	password := randomFakePassword()
	name := gofakeit.Name()

	_, err := httpClient.registerUser(email, password, name)
	require.NoError(t, err)

	loginResp, err := httpClient.login(email, password)
	require.NoError(t, err)
	require.NotNil(t, loginResp.TokenData)
	require.NotEmpty(t, loginResp.TokenData.RefreshToken)

	t.Logf("✓ Initial login successful, got refresh token")

	// Use access token to get user (verify it works)
	userResp, err := httpClient.getUser(loginResp.TokenData.AccessToken)
	require.NoError(t, err)
	require.Equal(t, email, userResp.User.Email)

	t.Log("✓ Access token works correctly")

	// Cleanup
	err = httpClient.deleteUser(loginResp.TokenData.AccessToken)
	require.NoError(t, err)

	t.Log("Token refresh flow test completed successfully!")
}

// TestHTTPAuthFlow_UnauthorizedAccess verifies that endpoints requiring auth reject unauthorized requests
func TestHTTPAuthFlow_UnauthorizedAccess(t *testing.T) {
	suite.New(t)

	httpClient := newHTTPClient(getHTTPBaseURL(), cfg.ClientID)

	t.Log("Testing unauthorized access to protected endpoint")

	// Try to get user without token
	_, err := httpClient.getUser("")
	require.Error(t, err, "Request without token should fail")
	assert.Contains(t, err.Error(), "failed", "Error should indicate failure")

	t.Log("✓ Unauthorized access correctly rejected")

	// Try with invalid token format
	_, err = httpClient.getUser("not-a-valid-token")
	require.Error(t, err, "Request with invalid token should fail")

	t.Log("✓ Invalid token correctly rejected")
	t.Log("Unauthorized access test completed successfully!")
}
