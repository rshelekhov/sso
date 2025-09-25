package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/require"
)

const clientID = "test-app-id"

func setup(t *testing.T) (*mocks.KeyStorage, *token.Service, *rsa.PrivateKey, []byte) {
	mockKeyStorage := new(mocks.KeyStorage)

	cfg := token.Config{
		PasswordHashParams: token.DefaultPasswordHashParams,
	}

	tokenService := token.NewService(cfg, mockKeyStorage, &mocks.NoOpMetricsRecorder{})

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
