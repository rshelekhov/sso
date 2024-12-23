package token

import (
	"context"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestExtractUserIDFromContext(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)
	mockKeyStorage.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

	claimKey := "user_id"
	claimValue := "test-user-id"

	ctx := createContextWithToken(t, privateKey, jwt.MapClaims{
		claimKey: claimValue,
	})

	t.Run("Success", func(t *testing.T) {
		userID, err := tokenService.ExtractUserIDFromContext(ctx, appID)
		require.NoError(t, err)
		require.Equal(t, claimValue, userID)

		mockKeyStorage.AssertExpectations(t)
	})

	t.Run("User ID not found", func(t *testing.T) {
		ctx = createContextWithToken(t, privateKey, jwt.MapClaims{})

		userID, err := tokenService.ExtractUserIDFromContext(ctx, appID)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrUserIDNotFoundInContext.Error())
		require.Empty(t, userID)

		mockKeyStorage.AssertExpectations(t)
	})

	t.Run("No token found in context", func(t *testing.T) {
		emptyCtx := context.Background()

		userID, err := tokenService.ExtractUserIDFromContext(emptyCtx, appID)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrNoTokenFoundInContext.Error())
		require.Empty(t, userID)
	})

	t.Run("Invalid token", func(t *testing.T) {
		ctx = context.WithValue(context.Background(), "access_token", "invalid-token")

		userID, err := tokenService.ExtractUserIDFromContext(ctx, appID)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToParseTokenWithClaims.Error())
		require.Empty(t, userID)
	})
}

func createContextWithToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) context.Context {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return context.WithValue(context.Background(), "access_token", tokenString)
}
