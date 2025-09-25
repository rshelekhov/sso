package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
)

func (s *Service) GenerateAndSavePrivateKey(clientID string) error {
	const method = "service.token.GenerateAndSavePrivateKey"

	ctx := context.Background()
	start := time.Now()

	privateKeyPEM, err := generatePrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	s.metrics.RecordPrivateKeyPEMGenerationDuration(ctx, clientID, time.Since(start).Seconds())

	if err = s.keyStorage.SavePrivateKey(clientID, privateKeyPEM); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (s *Service) PublicKey(clientID string) (any, error) {
	const method = "service.token.PublicKey"

	privateKey, err := s.getPrivateKeyFromPEM(clientID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}

	var publicKey any
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

func (s *Service) getPrivateKeyFromPEM(clientID string) (any, error) {
	privateKeyPEM, err := s.keyStorage.GetPrivateKey(clientID)
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
