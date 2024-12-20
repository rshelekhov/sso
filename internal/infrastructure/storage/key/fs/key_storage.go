package fs

import (
	"fmt"
	"os"
)

type KeyStorage struct {
	PrivateKeyPath string
}

func NewKeyStorage(cfg Config) (*KeyStorage, error) {
	return &KeyStorage{
		PrivateKeyPath: cfg.Path,
	}, nil
}

type Config struct {
	Path string
}

const privateKeyFilePathFormat = "%s/app_%s_private.pem"

func (s *KeyStorage) SavePrivateKey(appID string, privateKeyPEM []byte) error {
	// Ensure the keysPath directory exists
	if err := os.MkdirAll(s.PrivateKeyPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create keys path: %w", err)
	}

	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, appID)

	if err := os.WriteFile(privateKeyFilePath, privateKeyPEM, 0o600); err != nil {
		return fmt.Errorf("failed to save private key to file: %w", err)
	}

	return nil
}

func (s *KeyStorage) GetPrivateKey(appID string) ([]byte, error) {
	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.PrivateKeyPath, appID)

	privateKeyBytes, err := os.ReadFile(privateKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	return privateKeyBytes, nil
}
