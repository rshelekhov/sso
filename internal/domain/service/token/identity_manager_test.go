package token

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestTokenService_ExtractUserIDFromContext(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

	tests := []struct {
		name          string
		setupContext  func() context.Context
		mockBehavior  func()
		expectedID    string
		expectedError error
	}{
		{
			name: "Success",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), domain.AuthorizationHeader, createSignedToken(t, privateKey, jwt.MapClaims{
					"user_id": "test-user-id",
				}))
			},
			mockBehavior: func() {
				mockKeyStorage.EXPECT().GetPrivateKey(appID).
					Once().
					Return(privateKeyPEM, nil)
			},
			expectedID:    "test-user-id",
			expectedError: nil,
		},
		{
			name: "User ID not found",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), domain.AuthorizationHeader, createSignedToken(t, privateKey, jwt.MapClaims{}))
			},
			mockBehavior: func() {
				mockKeyStorage.EXPECT().GetPrivateKey(appID).
					Once().
					Return(privateKeyPEM, nil)
			},
			expectedID:    "",
			expectedError: domain.ErrUserIDNotFoundInContext,
		},
		{
			name: "No token found in context",
			setupContext: func() context.Context {
				return context.Background()
			},
			mockBehavior:  func() {}, // No need to mock anything, as the token will not be found
			expectedID:    "",
			expectedError: domain.ErrNoTokenFoundInContext,
		},
		{
			name: "Invalid token",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), domain.AuthorizationHeader, "invalid-token")
			},
			mockBehavior:  func() {}, // No need to mock anything, as the token not valid and will not be parsed
			expectedID:    "",
			expectedError: domain.ErrFailedToParseTokenWithClaims,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockBehavior()
			ctx := tt.setupContext()

			userID, err := tokenService.ExtractUserIDFromTokenInContext(ctx, appID)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.Empty(t, userID)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedID, userID)
			}

			mockKeyStorage.AssertExpectations(t)
		})
	}
}

func TestTokenService_ExtractUserRoleFromContext(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

	tests := []struct {
		name          string
		setupContext  func() context.Context
		mockBehavior  func()
		expectedRole  string
		expectedError error
	}{
		{
			name: "Success",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), domain.AuthorizationHeader, createSignedToken(t, privateKey, jwt.MapClaims{
					"role": "test-role",
				}))
			},
			mockBehavior: func() {
				mockKeyStorage.EXPECT().GetPrivateKey(appID).
					Once().
					Return(privateKeyPEM, nil)
			},
			expectedRole:  "test-role",
			expectedError: nil,
		},
		{
			name: "Role not found",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), domain.AuthorizationHeader, createSignedToken(t, privateKey, jwt.MapClaims{}))
			},
			mockBehavior: func() {
				mockKeyStorage.EXPECT().GetPrivateKey(appID).
					Once().
					Return(privateKeyPEM, nil)
			},
			expectedRole:  "",
			expectedError: domain.ErrRoleNotFoundInContext,
		},
		{
			name: "No token found in context",
			setupContext: func() context.Context {
				return context.Background()
			},
			mockBehavior:  func() {}, // No need to mock anything, as the token will not be found
			expectedRole:  "",
			expectedError: domain.ErrNoTokenFoundInContext,
		},
		{
			name: "Invalid token",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), domain.AuthorizationHeader, "invalid-token")
			},
			mockBehavior:  func() {}, // No need to mock anything, as the token not valid and will not be parsed
			expectedRole:  "",
			expectedError: domain.ErrFailedToParseTokenWithClaims,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockBehavior()
			ctx := tt.setupContext()

			role, err := tokenService.ExtractUserRoleFromTokenInContext(ctx, appID)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.Empty(t, role)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedRole, role)
			}

			mockKeyStorage.AssertExpectations(t)
		})
	}
}

func createSignedToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return tokenString
}
