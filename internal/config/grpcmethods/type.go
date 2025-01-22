package grpc

type GRPCConfig struct {
	PublicMethods []string `yaml:"public_methods"`
}

type Config struct {
	GRPC GRPCConfig `yaml:"grpc"`
}
