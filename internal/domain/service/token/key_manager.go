package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain"
)

func (s *Service) GenerateAndSavePrivateKey(appID string) error {
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

func (s *Service) PublicKey(appID string) (interface{}, error) {
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

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	pemBytes := pem.EncodeToMemory(privateKeyPEM)
	if pemBytes == nil {
		return nil, fmt.Errorf("failed to encode private key to PEM")
	}

	return pemBytes, nil
}

func (s *Service) getPrivateKeyFromPEM(appID string) (interface{}, error) {
	privateKeyPEM, err := s.keyStorage.GetPrivateKey(appID)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing the private key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unknown type of private key")
	}
}
