package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
)

type KeyManager interface {
	GenerateAndSavePrivateKey(appID string) error
	PublicKey(appID string) (interface{}, error)
}

func (s *service) GenerateAndSavePrivateKey(appID string) error {
	const method = "service.token.GenerateAndSavePrivateKey"

	privateKeyPEM, err := generatePrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	if err = s.keyStorage.SavePrivateKey(appID, privateKeyPEM); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (s *service) PublicKey(appID string) (interface{}, error) {
	const method = "service.token.PublicKey"

	privateKey, err := s.getPrivateKeyFromPEM(appID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}

	var publicKey interface{}
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return nil, domain.ErrUnknownTypeOfPublicKey
	}

	return publicKey, nil
}

func generatePrivateKeyPEM() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a PEM block with the DER encoded private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	b64 := []byte(base64.StdEncoding.EncodeToString(privateKeyBytes))
	privateKeyPEM := fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s-----END PRIVATE KEY-----\n", make64ColsString(b64))

	return []byte(privateKeyPEM), nil
}

func make64ColsString(input []byte) string {
	var result string

	for i := 0; i < len(input); i += 64 {
		end := i + 64
		if end > len(input) {
			end = len(input)
		}
		result += string(input[i:end]) + "\n"
	}

	return result
}

func (s *service) getPrivateKeyFromPEM(appID string) (interface{}, error) {
	privateKeyPEM, err := s.keyStorage.GetPrivateKey(appID)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing the private key")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}
