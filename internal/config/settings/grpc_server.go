package settings

import "time"

type GRPCServer struct {
	Host                  string        `mapstructure:"GRPC_SERVER_HOST" envDefault:"localhost"`
	Port                  string        `mapstructure:"GRPC_SERVER_PORT" envDefault:"44044"`
	Timeout               time.Duration `mapstructure:"GRPC_SERVER_TIMEOUT"`
	RetriesCount          int           `mapstructure:"GRPC_SERVER_RETRIES_COUNT" envDefault:"3"`
	GRPCMethodsConfigPath string        `mapstructure:"GRPC_METHODS_CONFIG_PATH" envDefault:"./config/grpc_methods.yaml"`
}
