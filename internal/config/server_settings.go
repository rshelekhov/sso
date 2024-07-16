package config

import "time"

type (
	ServerSettings struct {
		AppEnv            string             `mapstructure:"APP_ENV"`
		GRPCServer        GRPCServerConfig   `mapstructure:",squash"`
		Postgres          PostgresConfig     `mapstructure:",squash"`
		JWTAuth           JWTConfig          `mapstructure:",squash"`
		DefaultHashBcrypt HashBcryptConfig   `mapstructure:",squash"`
		KeyStorage        KeyStorageSettings `mapstructure:",squash"`
	}

	GRPCServerConfig struct {
		Port    string        `mapstructure:"GRPC_SERVER_PORT"`
		Timeout time.Duration `mapstructure:"GRPC_SERVER_TIMEOUT"`
	}

	PostgresConfig struct {
		Host string `mapstructure:"DB_HOST" envDefault:"localhost"`
		Port string `mapstructure:"DB_PORT" envDefault:"5432"`

		DBName   string `mapstructure:"DB_NAME"`
		User     string `mapstructure:"DB_USER"`
		Password string `mapstructure:"DB_PASSWORD"`

		SSLMode string `mapstructure:"DB_SSL_MODE" envDefault:"disable"`
		ConnURL string `mapstructure:"DB_CONN_URL"`

		ConnPoolSize int           `mapstructure:"DB_CONN_POOL_SIZE" envDefault:"10"`
		ReadTimeout  time.Duration `mapstructure:"DB_READ_TIMEOUT" envDefault:"5s"`
		WriteTimeout time.Duration `mapstructure:"DB_WRITE_TIMEOUT" envDefault:"5s"`
		IdleTimeout  time.Duration `mapstructure:"DB_IDLE_TIMEOUT" envDefault:"60s"`
		DialTimeout  time.Duration `mapstructure:"DB_DIAL_TIMEOUT" envDefault:"10s"`
	}

	JWTConfig struct {
		Issuer        string `mapstructure:"JWT_ISSUER"`
		SigningMethod string `mapstructure:"JWT_SIGNING_METHOD"`
		// KeysPath                 string        `mapstructure:"JWT_KEYS_PATH"`
		JWKSetTTL                time.Duration `mapstructure:"JWT_JWK_SET_TTL"`
		AccessTokenTTL           time.Duration `mapstructure:"JWT_ACCESS_TOKEN_TTL"`
		RefreshTokenTTL          time.Duration `mapstructure:"JWT_REFRESH_TOKEN_TTL"`
		RefreshTokenCookieDomain string        `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_DOMAIN"`
		RefreshTokenCookiePath   string        `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_PATH"`
	}

	HashBcryptConfig struct {
		Cost int    `mapstructure:"DEFAULT_HASH_BCRYPT_COST"`
		Salt string `mapstructure:"DEFAULT_HASH_BCRYPT_SALT"`
	}

	KeyStorageSettings struct {
		Type  KeyStorageType `mapstructure:"KEY_STORAGE_TYPE"`
		Local *KeyStorageLocal
		S3    *KeyStorageS3
	}

	KeyStorageLocal struct {
		Path string `mapstructure:"KEY_STORAGE_LOCAL_PATH"`
	}

	KeyStorageS3 struct {
		Region         string `mapstructure:"KEY_STORAGE_S3_REGION"`
		Bucket         string `mapstructure:"KEY_STORAGE_S3_BUCKET"`
		PrivateKeyPath string `mapstructure:"KEY_STORAGE_S3_KEY"`
		Endpoint       string `mapstructure:"KEY_STORAGE_S3_ENDPOINT"`
	}
)

type KeyStorageType string

const (
	KeyStorageTypeLocal KeyStorageType = "local"
	KeyStorageTypeS3    KeyStorageType = "s3"
)
