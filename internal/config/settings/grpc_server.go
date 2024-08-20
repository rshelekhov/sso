package settings

import "time"

type GRPCServer struct {
	Port    string        `mapstructure:"GRPC_SERVER_PORT" envDefault:"44044"`
	Timeout time.Duration `mapstructure:"GRPC_SERVER_TIMEOUT"`
}
