package storage

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/rshelekhov/sso/internal/storage/fs"
	"github.com/rshelekhov/sso/internal/storage/s3"
)

func NewKeyStorage(settings config.KeyStorageSettings) (port.KeyStorage, error) {
	switch settings.Type {
	case config.KeyStorageTypeLocal:
		if settings.Local == nil {
			return nil, le.ErrLocalKeyStorageSettingsEmpty
		}
		return fs.NewKeyStorage(*settings.Local)
	case config.KeyStorageTypeS3:
		if settings.S3 == nil {
			return nil, le.ErrS3KeyStorageSettingsEmpty
		}
		return s3.NewKeyStorage(*settings.S3)
	default:
		return nil, fmt.Errorf("unknown key storage type: %s", settings.Type)
	}
}
