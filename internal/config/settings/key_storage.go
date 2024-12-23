package settings

import (
	"fmt"
	"github.com/rshelekhov/sso/src/infrastructure/storage/key"
)

// KeyStorageType – what use for store private keys
type KeyStorageType string

const (
	KeyStorageTypeLocal KeyStorageType = "local"
	KeyStorageTypeS3    KeyStorageType = "s3"
)

type KeyStorage struct {
	Type  KeyStorageType `mapstructure:"KEY_STORAGE_TYPE" endDefault:"local"`
	Local *KeyStorageLocalParams
	S3    *KeyStorageS3Params
}

type KeyStorageLocalParams struct {
	Path string `mapstructure:"KEY_STORAGE_LOCAL_PATH" envDefault:"./certs"`
}

type KeyStorageS3Params struct {
	Region         string `mapstructure:"KEY_STORAGE_S3_REGION"`
	Bucket         string `mapstructure:"KEY_STORAGE_S3_BUCKET"`
	AccessKey      string `mapstructure:"KEY_STORAGE_S3_ACCESS_KEY"`
	SecretKey      string `mapstructure:"KEY_STORAGE_S3_SECRET_KEY"`
	PrivateKeyPath string `mapstructure:"KEY_STORAGE_S3_PRIVATE_KEY_PATH"`
	Endpoint       string `mapstructure:"KEY_STORAGE_S3_ENDPOINT"`
}

func ToKeysConfig(ks KeyStorage) (key.Config, error) {
	const op = "settings.KeyStorage.ToKeysConfig"

	storageType, err := validateAndConvertStorageType(ks.Type)
	if err != nil {
		return key.Config{}, fmt.Errorf("%s: %w", op, err)
	}

	return key.Config{
		Type:  storageType,
		Local: convertLocalParams(ks.Local),
		S3:    convertS3Params(ks.S3),
	}, nil
}

func validateAndConvertStorageType(storageType KeyStorageType) (key.StorageType, error) {
	switch storageType {
	case KeyStorageTypeLocal:
		return key.StorageTypeLocal, nil
	case KeyStorageTypeS3:
		return key.StorageTypeS3, nil
	case "":
		return "", fmt.Errorf("key storage type is empty")
	default:
		return "", fmt.Errorf("unknown key storage type: %s", storageType)
	}
}

func convertLocalParams(params *KeyStorageLocalParams) *key.StorageLocalParams {
	if params == nil {
		return nil
	}

	return &key.StorageLocalParams{
		Path: params.Path,
	}
}

func convertS3Params(params *KeyStorageS3Params) *key.StorageS3Params {
	if params == nil {
		return nil
	}

	return &key.StorageS3Params{
		Region:         params.Region,
		Bucket:         params.Bucket,
		AccessKey:      params.AccessKey,
		SecretKey:      params.SecretKey,
		PrivateKeyPath: params.PrivateKeyPath,
		Endpoint:       params.Endpoint,
	}
}
