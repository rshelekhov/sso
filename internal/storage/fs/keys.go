package fs

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/config"
	"os"
)

type KeyStorage struct {
	KeysPath string
}

func NewKeyStorage(settings config.KeyStorageLocal) (*KeyStorage, error) {
	return &KeyStorage{
		KeysPath: settings.Path,
	}, nil
}

const privateKeyFilePathFormat = "%s/app_%s_private.pem"

func (s *KeyStorage) SavePrivateKey(appID string, privateKeyPEM []byte) error {
	// Ensure the keysPath directory exists
	if err := os.MkdirAll(s.KeysPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create keys path: %w", err)
	}

	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.KeysPath, appID)

	if err := os.WriteFile(privateKeyFilePath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key to file: %w", err)
	}

	return nil
}

func (s *KeyStorage) GetPrivateKey(appID string) ([]byte, error) {
	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, s.KeysPath, appID)

	privateKeyBytes, err := os.ReadFile(privateKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	return privateKeyBytes, nil
}
