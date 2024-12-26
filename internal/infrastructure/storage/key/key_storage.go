package key

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/key/fs"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/key/s3"
)

var (
	ErrLocalKeyStorageSettingsEmpty = fmt.Errorf("local key storage settings are empty")
	ErrS3KeyStorageSettingsEmpty    = fmt.Errorf("s3 key storage settings are empty")
)

func NewStorage(cfg Config) (token.KeyStorage, error) {
	switch cfg.Type {
	case StorageTypeLocal:
		return newLocalKeyStorage(cfg)
	case StorageTypeS3:
		return newS3KeyStorage(cfg)
	default:
		return nil, fmt.Errorf("unknown key storage type: %s", cfg.Type)
	}
}

func newLocalKeyStorage(cfg Config) (token.KeyStorage, error) {
	if cfg.Local == nil {
		return nil, ErrLocalKeyStorageSettingsEmpty
	}

	localConfig := fs.Config{
		Path: cfg.Local.Path,
	}

	return fs.NewKeyStorage(localConfig)
}

func newS3KeyStorage(cfg Config) (token.KeyStorage, error) {
	if cfg.S3 == nil {
		return nil, ErrS3KeyStorageSettingsEmpty
	}

	s3Config := s3.Config{
		Region:         cfg.S3.Region,
		Bucket:         cfg.S3.Bucket,
		AccessKey:      cfg.S3.AccessKey,
		SecretKey:      cfg.S3.SecretKey,
		PrivateKeyPath: cfg.S3.PrivateKeyPath,
		Endpoint:       cfg.S3.Endpoint,
	}

	return s3.NewKeyStorage(s3Config)
}

type StorageType string

const (
	StorageTypeLocal StorageType = "local"
	StorageTypeS3    StorageType = "s3"
)

type Config struct {
	Type  StorageType
	Local *StorageLocalParams
	S3    *StorageS3Params
}

type StorageLocalParams struct {
	Path string
}

type StorageS3Params struct {
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	PrivateKeyPath string
	Endpoint       string
}
