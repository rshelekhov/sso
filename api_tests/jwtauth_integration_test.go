package api_tests

import (
	"context"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/rshelekhov/sso/pkg/jwtauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// setupJWTAuthManager creates a jwtauth manager with remote JWKS provider for testing
func setupJWTAuthManager(t *testing.T, st *suite.Suite) (jwtauth.Manager, func()) {
	t.Helper()

	// Get gRPC address from suite config
	grpcAddress := suite.GrpcAddress(st.Cfg)

	// Create remote JWKS provider that connects to SSO service
	jwksProvider, err := jwtauth.NewRemoteJWKSProvider(
		grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "Failed to create remote JWKS provider")

	// Create JWT manager with remote provider and client ID
	jwtManager := jwtauth.NewManager(
		jwksProvider,
		jwtauth.WithClientID(cfg.ClientID),
	)

	cleanup := func() {
		err := jwksProvider.Close()
		if err != nil {
			t.Logf("Failed to close JWKS provider: %v", err)
		}
	}

	return jwtManager, cleanup
}

// registerUserAndGetToken is a helper that registers a user and returns the access token
func registerUserAndGetToken(t *testing.T, ctx context.Context, st *suite.Suite) (string, string, *authv1.TokenData) {
	t.Helper()

	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	userID := respReg.GetUserId()
	require.NotEmpty(t, userID)

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)
	require.NotEmpty(t, token.GetAccessToken())

	return userID, email, token
}

// TestRemoteJWKSProvider_FetchJWKS tests that RemoteJWKSProvider can fetch JWKS from SSO
func TestRemoteJWKSProvider_FetchJWKS(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanup := setupJWTAuthManager(t, st)
	defer cleanup()

	// Get JWKS directly through the SSO service to verify it works
	// Add clientID to gRPC metadata as expected by SSO service
	md := metadata.Pairs("x-client-id", cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)
	jwksResp, err := st.AuthService.GetJWKS(ctx, &authv1.GetJWKSRequest{})
	require.NoError(t, err, "Failed to fetch JWKS from SSO")
	require.NotEmpty(t, jwksResp.GetJwks(), "JWKS should not be empty")

	// Verify JWKS structure
	jwks := jwksResp.GetJwks()
	assert.Greater(t, len(jwks), 0, "Should have at least one key")

	for _, jwk := range jwks {
		assert.NotEmpty(t, jwk.GetKid(), "Key ID should not be empty")
		assert.NotEmpty(t, jwk.GetKty(), "Key type should not be empty")
		assert.NotEmpty(t, jwk.GetAlg(), "Algorithm should not be empty")
		assert.NotEmpty(t, jwk.GetN(), "N parameter should not be empty")
		assert.NotEmpty(t, jwk.GetE(), "E parameter should not be empty")
	}

	// Verify that jwtManager can use the JWKS (we'll test token validation separately)
	require.NotNil(t, jwtManager, "JWT manager should be initialized")
}

// TestRemoteJWKSProvider_ValidateToken tests token validation using remote JWKS
func TestRemoteJWKSProvider_ValidateToken(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Register user and get token from SSO
	userID, email, tokenData := registerUserAndGetToken(t, ctx, st)
	accessToken := tokenData.GetAccessToken()

	// Parse and validate token using jwtauth manager
	parsedToken, err := jwtManager.ParseToken(cfg.ClientID, accessToken)
	require.NoError(t, err, "Token validation should succeed")
	require.NotNil(t, parsedToken, "Parsed token should not be nil")
	assert.True(t, parsedToken.Valid, "Token should be valid")

	// Extract claims
	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok, "Should be able to extract MapClaims")

	// Verify standard claims exist
	assert.NotEmpty(t, mapClaims["user_id"], "user_id claim should exist")
	assert.Equal(t, userID, mapClaims["user_id"], "user_id should match")
	assert.Equal(t, email, mapClaims["email"], "email should match")
	assert.Equal(t, cfg.ClientID, mapClaims["client_id"], "client_id should match")
	assert.Equal(t, cfg.Issuer, mapClaims["iss"], "issuer should match")

	// Verify device_id exists (SSO should set this)
	assert.NotEmpty(t, mapClaims["device_id"], "device_id claim should exist")

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// TestRemoteJWKSProvider_ValidateMultipleTokens tests validation of multiple tokens
func TestRemoteJWKSProvider_ValidateMultipleTokens(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Register multiple users and validate their tokens
	const numUsers = 3
	var tokens []*authv1.TokenData

	for i := 0; i < numUsers; i++ {
		userID, _, tokenData := registerUserAndGetToken(t, ctx, st)
		tokens = append(tokens, tokenData)

		// Validate each token
		parsedToken, err := jwtManager.ParseToken(cfg.ClientID, tokenData.GetAccessToken())
		require.NoError(t, err, "Token %d validation should succeed", i)
		require.True(t, parsedToken.Valid, "Token %d should be valid", i)

		// Verify user_id claim
		mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok, "Should be able to extract MapClaims for token %d", i)
		assert.Equal(t, userID, mapClaims["user_id"], "user_id should match for token %d", i)
	}

	// Cleanup all users
	for _, token := range tokens {
		params := cleanupParams{
			t:        t,
			st:       st,
			clientID: cfg.ClientID,
			token:    token,
		}
		cleanup(params, cfg.ClientID)
	}
}

// TestRemoteJWKSProvider_InvalidToken tests that invalid tokens are rejected
func TestRemoteJWKSProvider_InvalidToken(t *testing.T) {
	_, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "Empty token",
			token:       "",
			expectError: true,
		},
		{
			name:        "Malformed token",
			token:       "not.a.valid.jwt.token",
			expectError: true,
		},
		{
			name:        "Random string",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedToken, err := jwtManager.ParseToken(cfg.ClientID, tt.token)

			if tt.expectError {
				assert.Error(t, err, "Should return error for invalid token")
				if parsedToken != nil {
					assert.False(t, parsedToken.Valid, "Token should be invalid")
				}
			}
		})
	}
}

// TestRemoteJWKSProvider_TamperedToken tests that tampered tokens are rejected
func TestRemoteJWKSProvider_TamperedToken(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Get a valid token
	_, _, tokenData := registerUserAndGetToken(t, ctx, st)
	validToken := tokenData.GetAccessToken()

	// Tamper with the token by modifying the last character
	tamperedToken := validToken[:len(validToken)-5] + "XXXXX"

	// Try to validate tampered token
	parsedToken, err := jwtManager.ParseToken(cfg.ClientID, tamperedToken)
	assert.Error(t, err, "Should return error for tampered token")
	if parsedToken != nil {
		assert.False(t, parsedToken.Valid, "Tampered token should be invalid")
	}

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// TestRemoteJWKSProvider_CachePerformance tests JWKS caching behavior
func TestRemoteJWKSProvider_CachePerformance(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Get a token
	_, _, tokenData := registerUserAndGetToken(t, ctx, st)
	accessToken := tokenData.GetAccessToken()

	// First validation - will fetch JWKS
	start := time.Now()
	parsedToken1, err := jwtManager.ParseToken(cfg.ClientID, accessToken)
	firstValidationDuration := time.Since(start)
	require.NoError(t, err)
	require.True(t, parsedToken1.Valid)

	// Second validation - should use cached JWKS (faster)
	start = time.Now()
	parsedToken2, err := jwtManager.ParseToken(cfg.ClientID, accessToken)
	secondValidationDuration := time.Since(start)
	require.NoError(t, err)
	require.True(t, parsedToken2.Valid)

	// Note: We can't guarantee second is always faster due to various factors,
	// but we can at least verify both succeed
	t.Logf("First validation: %v, Second validation: %v", firstValidationDuration, secondValidationDuration)

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// Mock gRPC service for testing interceptor
type mockDownstreamService struct {
	receivedClaims *jwtauth.Claims
}

func (m *mockDownstreamService) TestMethod(ctx context.Context, req interface{}) (interface{}, error) {
	// Extract claims from context
	m.receivedClaims = jwtauth.ClaimsFromContext(ctx)
	return &struct{}{}, nil
}

// TestGRPCInterceptor_WithSSOToken tests gRPC interceptor with real SSO tokens
func TestGRPCInterceptor_WithSSOToken(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Register user and get token from SSO
	userID, email, tokenData := registerUserAndGetToken(t, ctx, st)
	accessToken := tokenData.GetAccessToken()

	// Create a mock service to receive the claims
	mockService := &mockDownstreamService{}

	// Create interceptor
	interceptor := jwtManager.UnaryServerInterceptor()

	// Create mock handler that extracts claims
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return mockService.TestMethod(ctx, req)
	}

	// Create gRPC metadata with token
	md := metadata.Pairs(
		jwtauth.AuthorizationHeader, accessToken,
		jwtauth.ClientIDHeader, cfg.ClientID,
	)
	ctxWithMetadata := metadata.NewIncomingContext(ctx, md)

	// Call interceptor
	_, err := interceptor(ctxWithMetadata, &struct{}{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.TestService/TestMethod",
	}, handler)

	require.NoError(t, err, "Interceptor should succeed with valid token")
	require.NotNil(t, mockService.receivedClaims, "Claims should be added to context")

	// Verify claims
	assert.Equal(t, userID, mockService.receivedClaims.UserID, "UserID should match")
	assert.Equal(t, email, mockService.receivedClaims.Email, "Email should match")
	assert.Equal(t, cfg.ClientID, mockService.receivedClaims.ClientID, "ClientID should match")
	assert.NotEmpty(t, mockService.receivedClaims.DeviceID, "DeviceID should be set")

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// TestGRPCInterceptor_RejectInvalidToken tests that interceptor rejects invalid tokens
func TestGRPCInterceptor_RejectInvalidToken(t *testing.T) {
	_, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Create interceptor
	interceptor := jwtManager.UnaryServerInterceptor()

	// Create mock handler
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return &struct{}{}, nil
	}

	tests := []struct {
		name        string
		token       string
		clientID    string
		expectError bool
	}{
		{
			name:        "No token",
			token:       "",
			clientID:    cfg.ClientID,
			expectError: true,
		},
		{
			name:        "Invalid token",
			token:       "invalid.token.value",
			clientID:    cfg.ClientID,
			expectError: true,
		},
		{
			name:        "No client ID",
			token:       "some.token.value",
			clientID:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create gRPC metadata
			md := metadata.New(map[string]string{})
			if tt.token != "" {
				md.Set(jwtauth.AuthorizationHeader, tt.token)
			}
			if tt.clientID != "" {
				md.Set(jwtauth.ClientIDHeader, tt.clientID)
			}

			ctxWithMetadata := metadata.NewIncomingContext(ctx, md)

			// Call interceptor
			_, err := interceptor(ctxWithMetadata, &struct{}{}, &grpc.UnaryServerInfo{
				FullMethod: "/test.TestService/TestMethod",
			}, handler)

			if tt.expectError {
				assert.Error(t, err, "Should return error for invalid token")
			}
		})
	}
}

// TestGRPCInterceptor_MissingMetadata tests interceptor with missing metadata
func TestGRPCInterceptor_MissingMetadata(t *testing.T) {
	_, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	interceptor := jwtManager.UnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return &struct{}{}, nil
	}

	// Call without metadata
	ctx := context.Background()
	_, err := interceptor(ctx, &struct{}{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.TestService/TestMethod",
	}, handler)

	assert.Error(t, err, "Should return error when metadata is missing")
}

// TestClaimsParsing_FromSSOToken tests claims parsing from SSO tokens
func TestClaimsParsing_FromSSOToken(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Register user and get token from SSO
	userID, email, tokenData := registerUserAndGetToken(t, ctx, st)
	accessToken := tokenData.GetAccessToken()

	// Parse token
	parsedToken, err := jwtManager.ParseToken(cfg.ClientID, accessToken)
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	// Extract MapClaims
	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	// Convert to structured Claims
	claims := jwtauth.FromMapClaims(mapClaims)
	require.NotNil(t, claims)

	// Verify standard claims
	assert.Equal(t, userID, claims.UserID, "UserID should match")
	assert.Equal(t, email, claims.Email, "Email should match")
	assert.Equal(t, cfg.ClientID, claims.ClientID, "ClientID should match")
	assert.Equal(t, cfg.Issuer, claims.Issuer, "Issuer should match")
	assert.NotEmpty(t, claims.DeviceID, "DeviceID should be set")

	// Verify registered claims
	assert.NotNil(t, claims.ExpiresAt, "ExpiresAt should be set")
	assert.NotNil(t, claims.IssuedAt, "IssuedAt should be set")

	// Verify expiration is in the future
	assert.True(t, claims.ExpiresAt.After(time.Now()), "Token should not be expired")

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// TestClaimsFromContext_InInterceptor tests extracting claims from context
func TestClaimsFromContext_InInterceptor(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Register user and get token
	userID, email, tokenData := registerUserAndGetToken(t, ctx, st)
	accessToken := tokenData.GetAccessToken()

	var capturedClaims *jwtauth.Claims

	// Create interceptor
	interceptor := jwtManager.UnaryServerInterceptor()

	// Create handler that captures claims from context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedClaims = jwtauth.ClaimsFromContext(ctx)
		return &struct{}{}, nil
	}

	// Create metadata with token
	md := metadata.Pairs(
		jwtauth.AuthorizationHeader, accessToken,
		jwtauth.ClientIDHeader, cfg.ClientID,
	)
	ctxWithMetadata := metadata.NewIncomingContext(ctx, md)

	// Call interceptor
	_, err := interceptor(ctxWithMetadata, &struct{}{}, &grpc.UnaryServerInfo{
		FullMethod: "/test.TestService/TestMethod",
	}, handler)

	require.NoError(t, err)
	require.NotNil(t, capturedClaims, "Claims should be available in context")

	// Verify claims
	assert.Equal(t, userID, capturedClaims.UserID)
	assert.Equal(t, email, capturedClaims.Email)
	assert.Equal(t, cfg.ClientID, capturedClaims.ClientID)

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// TestClaims_CustomFieldsExtraction tests custom claims extraction methods
func TestClaims_CustomFieldsExtraction(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Register user and get token
	_, _, tokenData := registerUserAndGetToken(t, ctx, st)
	accessToken := tokenData.GetAccessToken()

	// Parse token
	parsedToken, err := jwtManager.ParseToken(cfg.ClientID, accessToken)
	require.NoError(t, err)

	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	// Convert to structured Claims
	claims := jwtauth.FromMapClaims(mapClaims)

	// Test GetString on non-existent claim (standard claims are not in Extra)
	customStr := claims.GetString("non_existent")
	assert.Empty(t, customStr, "Should return empty string for non-existent claim")

	// Test GetInt64 on non-existent claim
	customInt := claims.GetInt64("non_existent")
	assert.Equal(t, int64(0), customInt, "Should return 0 for non-existent claim")

	// Test GetBool on non-existent claim
	customBool := claims.GetBool("non_existent")
	assert.False(t, customBool, "Should return false for non-existent claim")

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// TestClaims_HasRole tests role checking functionality
func TestClaims_HasRole(t *testing.T) {
	// This test is placeholder since SSO might not issue roles yet
	// If roles are added to tokens later, this test can be expanded
	claims := &jwtauth.Claims{
		Roles: []string{"user", "admin"},
	}

	assert.True(t, claims.HasRole("user"), "Should find 'user' role")
	assert.True(t, claims.HasRole("admin"), "Should find 'admin' role")
	assert.False(t, claims.HasRole("superadmin"), "Should not find 'superadmin' role")

	// Test with nil roles
	claimsWithoutRoles := &jwtauth.Claims{}
	assert.False(t, claimsWithoutRoles.HasRole("any"), "Should return false when roles is nil")
}

// TestClaims_GetRolesFromExtra tests extracting roles from custom fields
func TestClaims_GetRolesFromExtra(t *testing.T) {
	// Test with roles in Extra as []any
	claims := &jwtauth.Claims{
		Extra: map[string]any{
			"permissions": []any{"read", "write", "delete"},
		},
	}

	roles := claims.GetRolesFromExtra("permissions")
	assert.Equal(t, []string{"read", "write", "delete"}, roles)

	// Test with non-existent field
	emptyRoles := claims.GetRolesFromExtra("non_existent")
	assert.Empty(t, emptyRoles)

	// Test with roles as []string
	claimsWithStringRoles := &jwtauth.Claims{
		Extra: map[string]any{
			"groups": []string{"admin", "user"},
		},
	}

	groups := claimsWithStringRoles.GetRolesFromExtra("groups")
	assert.Equal(t, []string{"admin", "user"}, groups)
}

// TestErrorScenarios_ComprehensiveSuite tests various error conditions
func TestErrorScenarios_ComprehensiveSuite(t *testing.T) {
	ctx, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	// Get a valid token first for baseline
	userID, _, tokenData := registerUserAndGetToken(t, ctx, st)
	validToken := tokenData.GetAccessToken()

	// Verify valid token works
	parsedToken, err := jwtManager.ParseToken(cfg.ClientID, validToken)
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	tests := []struct {
		name        string
		token       string
		clientID    string
		shouldError bool
		description string
	}{
		{
			name:        "Valid token",
			token:       validToken,
			clientID:    cfg.ClientID,
			shouldError: false,
			description: "Baseline test - valid token should succeed",
		},
		{
			name:        "Empty token",
			token:       "",
			clientID:    cfg.ClientID,
			shouldError: true,
			description: "Empty token should be rejected",
		},
		{
			name:        "Malformed token - not enough parts",
			token:       "invalid.token",
			clientID:    cfg.ClientID,
			shouldError: true,
			description: "Token without proper JWT structure should be rejected",
		},
		{
			name:        "Malformed token - random string",
			token:       "thisisnotavalidjwttoken",
			clientID:    cfg.ClientID,
			shouldError: true,
			description: "Random string should be rejected",
		},
		{
			name:        "Invalid signature",
			token:       validToken[:len(validToken)-10] + "INVALIDXXX",
			clientID:    cfg.ClientID,
			shouldError: true,
			description: "Token with tampered signature should be rejected",
		},
		{
			name:        "Token with wrong client ID",
			token:       validToken,
			clientID:    "wrong-client-id",
			shouldError: true,
			description: "Token validated with wrong client ID should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedToken, err := jwtManager.ParseToken(tt.clientID, tt.token)

			if tt.shouldError {
				assert.Error(t, err, tt.description)
				if parsedToken != nil {
					assert.False(t, parsedToken.Valid, "Token should be marked as invalid")
				}
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, parsedToken, "Parsed token should not be nil")
				assert.True(t, parsedToken.Valid, "Token should be valid")

				// Verify claims are correct
				mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)
				assert.Equal(t, userID, mapClaims["user_id"])
			}
		})
	}

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    tokenData,
	}
	cleanup(params, cfg.ClientID)
}

// TestErrorScenarios_InterceptorErrors tests error propagation in gRPC interceptor
func TestErrorScenarios_InterceptorErrors(t *testing.T) {
	_, st := suite.New(t)

	jwtManager, cleanupManager := setupJWTAuthManager(t, st)
	defer cleanupManager()

	interceptor := jwtManager.UnaryServerInterceptor()
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return &struct{}{}, nil
	}

	tests := []struct {
		name             string
		setupMetadata    func() context.Context
		expectedErrorMsg string
	}{
		{
			name: "Missing metadata entirely",
			setupMetadata: func() context.Context {
				return context.Background()
			},
			expectedErrorMsg: "metadata",
		},
		{
			name: "Missing authorization header",
			setupMetadata: func() context.Context {
				md := metadata.Pairs(jwtauth.ClientIDHeader, cfg.ClientID)
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectedErrorMsg: "authorization",
		},
		{
			name: "Missing client ID header",
			setupMetadata: func() context.Context {
				md := metadata.Pairs(jwtauth.AuthorizationHeader, "some.token.value")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectedErrorMsg: "token is malformed",
		},
		{
			name: "Invalid token format",
			setupMetadata: func() context.Context {
				md := metadata.Pairs(
					jwtauth.AuthorizationHeader, "not-a-valid-token",
					jwtauth.ClientIDHeader, cfg.ClientID,
				)
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectedErrorMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupMetadata()

			_, err := interceptor(ctx, &struct{}{}, &grpc.UnaryServerInfo{
				FullMethod: "/test.TestService/TestMethod",
			}, handler)

			assert.Error(t, err, "Interceptor should return error")
			if tt.expectedErrorMsg != "" {
				assert.Contains(t, err.Error(), tt.expectedErrorMsg,
					"Error message should mention the missing/invalid component")
			}
		})
	}
}

// TestErrorScenarios_ClaimsExtraction tests error handling when extracting claims
func TestErrorScenarios_ClaimsExtraction(t *testing.T) {
	// Test MustGetClaims with empty context
	ctx := context.Background()
	claims, err := jwtauth.MustGetClaims(ctx)
	assert.Error(t, err, "Should return error when claims not in context")
	assert.Nil(t, claims, "Claims should be nil")
	assert.ErrorIs(t, err, jwtauth.ErrTokenNotFoundInContext)

	// Test ClaimsFromContext with empty context
	claimsFromCtx := jwtauth.ClaimsFromContext(ctx)
	assert.Nil(t, claimsFromCtx, "ClaimsFromContext should return nil for empty context")
}
