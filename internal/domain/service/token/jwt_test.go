package token

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewAccessToken(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

	claimKey := "user_id"
	claimValue := "test-user-id"
	additionalClaims := map[string]interface{}{
		claimKey: claimValue,
	}

	t.Run("Happy Path", func(t *testing.T) {
		kid := "test-kid"

		mockKeyStorage.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

		tokenString, err := tokenService.NewAccessToken(appID, kid, additionalClaims)
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)

		claims := token.Claims.(jwt.MapClaims)
		require.Equal(t, claimValue, claims[claimKey])
		require.Equal(t, kid, token.Header["kid"])

		mockKeyStorage.AssertExpectations(t)
	})

	t.Run("Empty appID", func(t *testing.T) {
		emptyAppID := ""

		tokenString, err := tokenService.NewAccessToken(emptyAppID, "test-kid", additionalClaims)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrAppIDIsNotAllowed.Error())
		require.Empty(t, tokenString)
	})

	t.Run("Empty kid", func(t *testing.T) {
		kid := ""

		tokenString, err := tokenService.NewAccessToken(appID, kid, additionalClaims)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrEmptyKidIsNotAllowed.Error())
		require.Empty(t, tokenString)
	})
}

func TestGetKeyID(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

	t.Run("valid appID", func(t *testing.T) {
		mockKeyStorage.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

		publicKey := &privateKey.PublicKey
		der, err := x509.MarshalPKIXPublicKey(publicKey)
		require.NoError(t, err)
		s := sha1.Sum(der)
		expectedKeyID := base64.URLEncoding.EncodeToString(s[:])

		keyID, err := tokenService.Kid(appID)
		require.NoError(t, err)
		require.Equal(t, expectedKeyID, keyID)

		mockKeyStorage.AssertExpectations(t)
	})

	t.Run("empty appID", func(t *testing.T) {
		emptyAppID := ""

		keyID, err := tokenService.Kid(emptyAppID)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrAppIDIsNotAllowed.Error())
		require.Empty(t, keyID)
	})
}
