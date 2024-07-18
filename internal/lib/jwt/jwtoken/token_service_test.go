package jwtoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken/mocks"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"strings"
	"testing"
	"time"
)

const (
	appID      = "test-app-id"
	emptyAppID = ""
)

// Setup mocks, service and keys
func setup(t *testing.T) (*mocks.MockKeyStorage, *Service, *rsa.PrivateKey, []byte) {
	keyStorageMock := new(mocks.MockKeyStorage)

	// Create the service with the mock KeyStorage
	service := NewService(
		"test-issuer",
		"RS256",
		keyStorageMock,
		time.Hour,
		time.Minute*15,
		time.Hour*24*30,
		"example.com",
		"/",
		10,
		"some_salt",
	)

	// Generate a test RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode the private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return keyStorageMock, service, privateKey, privateKeyPEM
}

// Create a context with JWT token
func createContextWithToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) context.Context {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	md := metadata.Pairs("access_token", tokenString)
	return metadata.NewIncomingContext(context.Background(), md)
}

// ===========================================================================
//   Tests for GeneratePrivateKey
// ===========================================================================

func TestGeneratePrivateKeyPEM(t *testing.T) {
	privateKeyPEM, err := generatePrivateKeyPEM()
	require.NoError(t, err)

	// Check if the generated PEM starts and ends with the correct headers
	expectedHeader := "-----BEGIN PRIVATE KEY-----"
	expectedFooter := "-----END PRIVATE KEY-----"
	privateKeyPEMString := string(privateKeyPEM)
	require.True(t, strings.HasPrefix(privateKeyPEMString, expectedHeader))
	require.True(t, strings.HasSuffix(privateKeyPEMString, expectedFooter+"\n"))

	// Extract the base64 part and decode it
	base64Data := privateKeyPEMString[len(expectedHeader)+1 : len(privateKeyPEMString)-len(expectedFooter)-1]
	privateKeyBytes, err := base64.StdEncoding.DecodeString(base64Data)
	require.NoError(t, err)

	// Parse the DER encoded private key
	_, err = x509.ParsePKCS1PrivateKey(privateKeyBytes)
	require.NoError(t, err)
}

func TestGetPrivateKeyFromPEM(t *testing.T) {
	keyStorageMock, service, privateKey, privateKeyPEM := setup(t)

	// Setup expectations
	keyStorageMock.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

	// Call the method
	result, err := service.getPrivateKeyFromPEM(appID)
	require.NoError(t, err)
	require.IsType(t, &rsa.PrivateKey{}, result)
	require.Equal(t, privateKey, result.(*rsa.PrivateKey))

	// Assert that the expectations were met
	keyStorageMock.AssertExpectations(t)
}

func TestGetPublicKey_RSA(t *testing.T) {
	keyStorageMock, service, privateKey, privateKeyPEM := setup(t)

	keyStorageMock.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

	publicKey, err := service.GetPublicKey(appID)
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, publicKey)
	require.Equal(t, &privateKey.PublicKey, publicKey.(*rsa.PublicKey))

	keyStorageMock.AssertExpectations(t)
}

// ===========================================================================
//   Tests for NewAccessToken
// ===========================================================================

func TestNewAccessToken(t *testing.T) {
	claimKey := "user_id"
	claimValue := "test-user-id"
	additionalClaims := map[string]interface{}{
		claimKey: claimValue,
	}

	t.Run("Happy Path", func(t *testing.T) {
		keyStorageMock, service, privateKey, privateKeyPEM := setup(t)
		kid := "test-kid"

		keyStorageMock.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

		tokenString, err := service.NewAccessToken(appID, kid, additionalClaims)
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return &privateKey.PublicKey, nil
		})
		require.NoError(t, err)
		require.True(t, token.Valid)

		claims := token.Claims.(jwt.MapClaims)
		require.Equal(t, claimValue, claims[claimKey])
		require.Equal(t, kid, token.Header[Kid])

		keyStorageMock.AssertExpectations(t)
	})

	t.Run("Empty Kid", func(t *testing.T) {
		keyStorageMock, service, _, _ := setup(t)
		kid := ""

		_, err := service.NewAccessToken(appID, kid, additionalClaims)
		require.Error(t, err)
		require.Contains(t, err.Error(), le.ErrEmptyKidIsNotAllowed)

		keyStorageMock.AssertExpectations(t)
	})
}

// ===========================================================================
//   Tests for GetKeyID
// ===========================================================================

func TestGetKeyID(t *testing.T) {
	keyStorageMock, service, privateKey, privateKeyPEM := setup(t)

	t.Run("valid appID", func(t *testing.T) {
		keyStorageMock.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

		publicKey := &privateKey.PublicKey
		der, err := x509.MarshalPKIXPublicKey(publicKey)
		require.NoError(t, err)
		s := sha1.Sum(der)
		expectedKeyID := base64.URLEncoding.EncodeToString(s[:])

		keyID, err := service.GetKeyID(appID)
		require.NoError(t, err)
		require.Equal(t, expectedKeyID, keyID)

		keyStorageMock.AssertExpectations(t)
	})

	t.Run("empty appID", func(t *testing.T) {
		keyID, err := service.GetKeyID(emptyAppID)
		require.Error(t, err)
		require.Contains(t, err.Error(), le.ErrEmptyAppIDIsNotAllowed)
		require.Empty(t, keyID)
	})
}

// ===========================================================================
//   Tests for GetUserID
// ===========================================================================

func TestGetUserID(t *testing.T) {
	keyStorageMock, service, privateKey, privateKeyPEM := setup(t)
	keyStorageMock.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

	claimKey := "user_id"
	claimValue := "test-user-id"

	ctx := createContextWithToken(t, privateKey, jwt.MapClaims{
		claimKey: claimValue,
	})

	t.Run("success", func(t *testing.T) {
		userID, err := service.GetUserID(ctx, appID, claimKey)
		require.NoError(t, err)
		require.Equal(t, claimValue, userID)
		keyStorageMock.AssertExpectations(t)
	})

	t.Run("user ID not found", func(t *testing.T) {
		userID, err := service.GetUserID(ctx, appID, "non_existent_key")
		require.Error(t, err)
		require.Equal(t, le.ErrUserIDNotFoundInCtx, err)
		require.Empty(t, userID)
	})

	t.Run("no token in context", func(t *testing.T) {
		emptyCtx := context.Background()
		userID, err := service.GetUserID(emptyCtx, appID, claimKey)
		require.Error(t, err)
		require.Equal(t, le.ErrNoMetaDataFoundInCtx, err)
		require.Empty(t, userID)
	})

	t.Run("invalid token", func(t *testing.T) {
		invalidTokenCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("access_token", "invalid.token.here"))
		userID, err := service.GetUserID(invalidTokenCtx, appID, claimKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "token is malformed")
		require.Empty(t, userID)
	})
}
