package config

import "time"

type ServerSettings struct {
	AppEnv            string               `mapstructure:"APP_ENV"`
	GRPCServer        GRPCServerSettings   `mapstructure:",squash"`
	Postgres          PostgresSettings     `mapstructure:",squash"`
	JWTAuth           JWTSettings          `mapstructure:",squash"`
	DefaultHashBcrypt HashBcryptSettings   `mapstructure:",squash"`
	KeyStorage        KeyStorageSettings   `mapstructure:",squash"`
	MailService       EmailServiceSettings `mapstructure:",squash"`
}

type GRPCServerSettings struct {
	Port    string        `mapstructure:"GRPC_SERVER_PORT" envDefault:"44044"`
	Timeout time.Duration `mapstructure:"GRPC_SERVER_TIMEOUT"`
}

type PostgresSettings struct {
	ConnURL      string        `mapstructure:"DB_CONN_URL"`
	ConnPoolSize int           `mapstructure:"DB_CONN_POOL_SIZE" envDefault:"10"`
	ReadTimeout  time.Duration `mapstructure:"DB_READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout time.Duration `mapstructure:"DB_WRITE_TIMEOUT" envDefault:"5s"`
	IdleTimeout  time.Duration `mapstructure:"DB_IDLE_TIMEOUT" envDefault:"60s"`
	DialTimeout  time.Duration `mapstructure:"DB_DIAL_TIMEOUT" envDefault:"10s"`
}

type JWTSettings struct {
	Issuer                   string        `mapstructure:"JWT_ISSUER"`
	SigningMethod            string        `mapstructure:"JWT_SIGNING_METHOD"`
	JWKSetTTL                time.Duration `mapstructure:"JWT_JWK_SET_TTL"`
	AccessTokenTTL           time.Duration `mapstructure:"JWT_ACCESS_TOKEN_TTL"`
	RefreshTokenTTL          time.Duration `mapstructure:"JWT_REFRESH_TOKEN_TTL"`
	RefreshTokenCookieDomain string        `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_DOMAIN"`
	RefreshTokenCookiePath   string        `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_PATH"`
}

type HashBcryptSettings struct {
	Cost int    `mapstructure:"DEFAULT_HASH_BCRYPT_COST"`
	Salt string `mapstructure:"DEFAULT_HASH_BCRYPT_SALT"`
}

// KeyStorageType – what use for store private keys
type KeyStorageType string

const (
	KeyStorageTypeLocal KeyStorageType = "local"
	KeyStorageTypeS3    KeyStorageType = "s3"
)

type KeyStorageSettings struct {
	Type  KeyStorageType `mapstructure:"KEY_STORAGE_TYPE" endDefault:"local"`
	Local *KeyStorageLocal
	S3    *KeyStorageS3
}

type KeyStorageLocal struct {
	Path string `mapstructure:"KEY_STORAGE_LOCAL_PATH" envDefault:"./certs"`
}

type KeyStorageS3 struct {
	Region         string `mapstructure:"KEY_STORAGE_S3_REGION"`
	Bucket         string `mapstructure:"KEY_STORAGE_S3_BUCKET"`
	AccessKey      string `mapstructure:"KEY_STORAGE_S3_ACCESS_KEY"`
	SecretKey      string `mapstructure:"KEY_STORAGE_S3_SECRET_KEY"`
	PrivateKeyPath string `mapstructure:"KEY_STORAGE_S3_PRIVATE_KEY_PATH"`
	Endpoint       string `mapstructure:"KEY_STORAGE_S3_ENDPOINT"`
}

// EmailServiceType - how to send email to clients
type EmailServiceType string

const (
	EmailServiceMailgun EmailServiceType = "mailgun"
	EmailServiceMock    EmailServiceType = "mock"
)

type EmailServiceSettings struct {
	Type    EmailServiceType `mapstructure:"EMAIL_SERVICE_TYPE" envDefault:"mock"`
	Mailgun *MailgunEmailServiceSettings
}

type MailgunEmailServiceSettings struct {
	Domain        string `mapstructure:"EMAIL_MAILGUN_DOMAIN"`
	PrivateAPIKey string `mapstructure:"EMAIL_MAILGUN_PRIVATE_API_KEY"`
	Sender        string `mapstructure:"EMAIL_SENDER"`
}
