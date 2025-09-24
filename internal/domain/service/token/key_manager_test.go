package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndSavePrivateKey(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)

	cfg := token.Config{
		PasswordHashParams: token.DefaultPasswordHashParams,
	}

	tokenService := token.NewService(cfg, mockKeyStorage, &mocks.NoOpMetricsRecorder{})

	mockKeyStorage.EXPECT().SavePrivateKey(clientID, mock.Anything).
		Once().
		Return(nil)

	err := tokenService.GenerateAndSavePrivateKey(clientID)
	require.NoError(t, err)
}

func TestPublicKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

		mockKeyStorage.EXPECT().GetPrivateKey(clientID).
			Once().
			Return(privateKeyPEM, nil)

		publicKey, err := tokenService.PublicKey(clientID)
		require.NoError(t, err)
		require.IsType(t, &rsa.PublicKey{}, publicKey)
		require.Equal(t, &privateKey.PublicKey, publicKey.(*rsa.PublicKey))
	})

	t.Run("Error — Unknown type", func(t *testing.T) {
		mockKeyStorage := new(mocks.KeyStorage)

		cfg := token.Config{
			PasswordHashParams: token.DefaultPasswordHashParams,
		}

		tokenService := token.NewService(cfg, mockKeyStorage, &mocks.NoOpMetricsRecorder{})

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

		mockKeyStorage.EXPECT().GetPrivateKey(clientID).Return(privateKeyPEM, nil)

		_, err = tokenService.PublicKey(clientID)
		require.NotEmpty(t, err)
	})
}
