package token

import (
	"context"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/stretchr/testify/require"
	"testing"
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
				return createContextWithToken(t, privateKey, jwt.MapClaims{
					"user_id": "test-user-id",
				})
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
				return createContextWithToken(t, privateKey, jwt.MapClaims{})
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
			mockBehavior:  func() {},
			expectedID:    "",
			expectedError: domain.ErrNoTokenFoundInContext,
		},
		{
			name: "Invalid token",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), "access_token", "invalid-token")
			},
			mockBehavior:  func() {},
			expectedID:    "",
			expectedError: domain.ErrFailedToParseTokenWithClaims,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockBehavior()
			ctx := tt.setupContext()

			userID, err := tokenService.ExtractUserIDFromContext(ctx, appID)

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

func createContextWithToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) context.Context {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return context.WithValue(context.Background(), "access_token", tokenString)
}
