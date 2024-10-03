package settings

import "time"

type MongoStorageParams struct {
	ConnectionString string `mapstructure:"DB_MONGO_CONN_STRING"`
	DatabaseName     string `mapstructure:"DB_MONGO_DATABASE_NAME"`
}

// TODO: Update env variables in env files
type PostgresStorageParams struct {
	ConnURL      string        `mapstructure:"DB_POSTGRES_CONN_URL"`
	ConnPoolSize int           `mapstructure:"DB_POSTGRES_CONN_POOL_SIZE" envDefault:"10"`
	ReadTimeout  time.Duration `mapstructure:"DB_POSTGRES_READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout time.Duration `mapstructure:"DB_POSTGRES_WRITE_TIMEOUT" envDefault:"5s"`
	IdleTimeout  time.Duration `mapstructure:"DB_POSTGRES_IDLE_TIMEOUT" envDefault:"60s"`
	DialTimeout  time.Duration `mapstructure:"DB_POSTGRES_DIAL_TIMEOUT" envDefault:"10s"`
}
