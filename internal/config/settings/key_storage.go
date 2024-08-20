package settings

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
