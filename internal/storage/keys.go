package storage

import (
	"fmt"

	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/rshelekhov/sso/internal/storage/fs"
	"github.com/rshelekhov/sso/internal/storage/s3"
)

func NewKeyStorage(storage settings.KeyStorage) (port.KeyStorage, error) {
	switch storage.Type {
	case settings.KeyStorageTypeLocal:
		if storage.Local == nil {
			return nil, le.ErrLocalKeyStorageSettingsEmpty
		}
		return fs.NewKeyStorage(*storage.Local)
	case settings.KeyStorageTypeS3:
		if storage.S3 == nil {
			return nil, le.ErrS3KeyStorageSettingsEmpty
		}
		return s3.NewKeyStorage(*storage.S3)
	default:
		return nil, fmt.Errorf("unknown key storage type: %s", storage.Type)
	}
}
