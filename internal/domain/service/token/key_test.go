package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/rshelekhov/sso/src/domain/service/token/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestGenerateAndSavePrivateKey(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)

	cfg := Config{
		PasswordHashParams: defaultPasswordHashParams,
	}

	tokenService := NewService(cfg, mockKeyStorage)

	mockKeyStorage.
		On("SavePrivateKey", appID, mock.Anything).
		Once().
		Return(nil)

	err := tokenService.GenerateAndSavePrivateKey(appID)
	require.NoError(t, err)
}

func TestPublicKey(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

	mockKeyStorage.
		On("GetPrivateKey", appID).
		Once().
		Return(privateKeyPEM, nil)

	publicKey, err := tokenService.PublicKey(appID)
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, publicKey)
	require.Equal(t, &privateKey.PublicKey, publicKey.(*rsa.PublicKey))
}

func TestPublicKey_UnknownType(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)

	cfg := Config{
		PasswordHashParams: defaultPasswordHashParams,
	}

	tokenService := NewService(cfg, mockKeyStorage)

	// Generate a test private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode the private key to PEM format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	mockKeyStorage.On("GetPrivateKey", appID).Return(privateKeyPEM, nil)

	_, err = tokenService.PublicKey(appID)
	require.NotEmpty(t, err)
}

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
