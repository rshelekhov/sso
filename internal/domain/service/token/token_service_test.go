package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/require"
	"testing"
)

const appID = "test-app-id"

func setup(t *testing.T) (*mocks.KeyStorage, *Service, *rsa.PrivateKey, []byte) {
	mockKeyStorage := new(mocks.KeyStorage)

	cfg := Config{
		PasswordHashParams: defaultPasswordHashParams,
	}

	tokenService := NewService(cfg, mockKeyStorage)

	// Generate a test RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode the private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return mockKeyStorage, tokenService, privateKey, privateKeyPEM
}
