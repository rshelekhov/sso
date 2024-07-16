package fs

import "github.com/rshelekhov/sso/internal/config"

type KeyStorage struct {
	KeysPath string
}

func NewKeyStorage(settings config.KeyStorageLocal) *KeyStorage {
	return &KeyStorage{
		KeysPath: settings.Path,
	}
}
