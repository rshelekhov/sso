package settings

import "time"

type AuthStorageType string

const (
	AuthStorageTypeDefault  = "default"
	AuthStorageTypeMongo    = "mongo"
	AuthStorageTypePostgres = "postgres"
)

// TODO: add env variable to .env file
type AuthStorage struct {
	Type     AuthStorageType `mapstructure:"AUTH_STORAGE_TYPE" endDefault:"default"`
	Mongo    *MongoStorageParams
	Postgres *PostgresStorageParams
}

// TODO: remove
type Postgres struct {
	ConnURL      string        `mapstructure:"DB_POSTGRES_CONN_URL"`
	ConnPoolSize int           `mapstructure:"DB_POSTGRES_CONN_POOL_SIZE" envDefault:"10"`
	ReadTimeout  time.Duration `mapstructure:"DB_POSTGRES_READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout time.Duration `mapstructure:"DB_POSTGRES_WRITE_TIMEOUT" envDefault:"5s"`
	IdleTimeout  time.Duration `mapstructure:"DB_POSTGRES_IDLE_TIMEOUT" envDefault:"60s"`
	DialTimeout  time.Duration `mapstructure:"DB_POSTGRES_DIAL_TIMEOUT" envDefault:"10s"`
}
