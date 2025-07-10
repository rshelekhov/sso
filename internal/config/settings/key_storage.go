package settings

import (
	"fmt"

	"github.com/rshelekhov/sso/internal/infrastructure/storage/key"
)

type KeyStorageType string

const (
	KeyStorageTypeLocal KeyStorageType = "local"
	KeyStorageTypeS3    KeyStorageType = "s3"
)

type KeyStorage struct {
	Type  KeyStorageType         `yaml:"Type" default:"local"`
	Local *KeyStorageLocalParams `yaml:"Local"`
	S3    *KeyStorageS3Params    `yaml:"S3"`
}

type KeyStorageLocalParams struct {
	Path string `yaml:"Path" default:"./certs"`
}

type KeyStorageS3Params struct {
	Region         string `yaml:"Region"`
	Bucket         string `yaml:"Bucket"`
	AccessKey      string `yaml:"AccessKey"`
	SecretKey      string `yaml:"SecretKey"`
	PrivateKeyPath string `yaml:"PrivateKeyPath"`
	Endpoint       string `yaml:"Endpoint"`
	ForcePathStyle bool   `yaml:"ForcePathStyle"`
}

func ToKeyStorageConfig(ks KeyStorage) (key.Config, error) {
	const op = "settings.KeyStorage.ToKeyStorageConfig"

	storageType, err := validateAndConvertKeyStorageType(ks.Type)
	if err != nil {
		return key.Config{}, fmt.Errorf("%s: %w", op, err)
	}

	return key.Config{
		Type:  storageType,
		Local: convertLocalParams(ks.Local),
		S3:    convertS3Params(ks.S3),
	}, nil
}

func validateAndConvertKeyStorageType(storageType KeyStorageType) (key.StorageType, error) {
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
		ForcePathStyle: params.ForcePathStyle,
	}
}
