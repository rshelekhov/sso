package config

import (
	"flag"
	"log"
	"os"

	"github.com/rshelekhov/sso/internal/config/settings"

	"github.com/spf13/viper"
)

//nolint:revive
const CONFIG_PATH = "CONFIG_PATH"

func MustLoad() *ServerSettings {
	configPath := fetchConfigPath()

	if configPath == "" {
		panic("config path is empty")
	}

	return MustLoadPath(configPath)
}

func MustLoadPath(configPath string) *ServerSettings {
	cfg := ServerSettings{}

	viper.SetConfigFile(configPath)

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("error finding or reading config file: %s", err)
	}

	viper.AutomaticEnv()

	err = viper.Unmarshal(&cfg)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct: %s: ", err)
	}

	loadStorageConfig(&cfg)
	loadKeyStorageConfig(&cfg)
	loadPasswordHashConfig(&cfg)

	return &cfg
}

// Load storage configuration based on type
func loadStorageConfig(cfg *ServerSettings) {
	switch cfg.Storage.Type {
	case settings.StorageTypeMongo:
		cfg.Storage.Mongo = loadMongoConfig()
	case settings.StorageTypePostgres:
		cfg.Storage.Postgres = loadPostgresConfig()
	default:
		log.Fatalf("unknown storage type: %s", cfg.Storage.Type)
	}
}

func loadMongoConfig() *settings.MongoParams {
	var mongo settings.MongoParams
	err := viper.Unmarshal(&mongo)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct with settings for mongo: %s: ", err)
	}
	return &mongo
}

func loadPostgresConfig() *settings.PostgresParams {
	var postgres settings.PostgresParams
	err := viper.Unmarshal(&postgres)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct with settings for postgres: %s: ", err)
	}
	return &postgres
}

// Load key storage configuration based on type
func loadKeyStorageConfig(cfg *ServerSettings) {
	switch cfg.KeyStorage.Type {
	case settings.KeyStorageTypeLocal:
		cfg.KeyStorage.Local = loadKeyStorageLocalConfig()
	case settings.KeyStorageTypeS3:
		cfg.KeyStorage.S3 = loadKeyStorageS3Config()
	default:
		log.Fatalf("unknown key storage type: %s", cfg.KeyStorage.Type)
	}
}

func loadKeyStorageLocalConfig() *settings.KeyStorageLocalParams {
	var local settings.KeyStorageLocalParams
	err := viper.Unmarshal(&local)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct with settings for key local storage: %s: ", err)
	}
	return &local
}

func loadKeyStorageS3Config() *settings.KeyStorageS3Params {
	var s3 settings.KeyStorageS3Params
	err := viper.Unmarshal(&s3)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct with settings for key s3 storage: %s: ", err)
	}
	return &s3
}

// Load password hash configuration based on type
func loadPasswordHashConfig(cfg *ServerSettings) {
	switch cfg.PasswordHash.Type {
	case settings.PasswordHashDefault, settings.PasswordHashArgon2:
		cfg.PasswordHash.Argon = loadArgon2Config()
	case settings.PasswordHashBcrypt:
		cfg.PasswordHash.Bcrypt = loadBcryptConfig()
	default:
		log.Fatalf("unknown password hash type: %s", cfg.PasswordHash.Type)
	}
}

func loadArgon2Config() *settings.PasswordHashArgon2Params {
	var argon settings.PasswordHashArgon2Params
	err := viper.Unmarshal(&argon)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct with settings for password hash argon2: %s: ", err)
	}
	return &argon
}

func loadBcryptConfig() *settings.PasswordHashBcryptParams {
	var bcrypt settings.PasswordHashBcryptParams
	err := viper.Unmarshal(&bcrypt)
	if err != nil {
		log.Fatalf("error unmarshalling config file into struct with settings for password hash bcrypt: %s: ", err)
	}
	return &bcrypt
}

// fetchConfigPath fetches config path from command line flag or environment variable.
// Priority: flag > env > default.
// Default value is empty string.
func fetchConfigPath() string {
	var v string

	flag.StringVar(&v, "config", "", "path to config file")
	flag.Parse()

	if v == "" {
		v = os.Getenv(CONFIG_PATH)
	}

	return v
}
