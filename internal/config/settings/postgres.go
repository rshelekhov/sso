package settings

import "time"

type Postgres struct {
	ConnURL      string        `mapstructure:"DB_CONN_URL"`
	ConnPoolSize int           `mapstructure:"DB_CONN_POOL_SIZE" envDefault:"10"`
	ReadTimeout  time.Duration `mapstructure:"DB_READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout time.Duration `mapstructure:"DB_WRITE_TIMEOUT" envDefault:"5s"`
	IdleTimeout  time.Duration `mapstructure:"DB_IDLE_TIMEOUT" envDefault:"60s"`
	DialTimeout  time.Duration `mapstructure:"DB_DIAL_TIMEOUT" envDefault:"10s"`
}
