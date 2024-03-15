package config

import "time"

type (
	ServerSettings struct {
		AppEnv     string           `mapstructure:"APP_ENV"`
		GRPCServer GRPCServerConfig `mapstructure:",squash"`
		Postgres   PostgresConfig   `mapstructure:",squash"`
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
)
