package grpcmethods

type ServiceConfig struct {
	PublicMethods []string `yaml:"public_methods"`
}

type Config struct {
	Service ServiceConfig `yaml:"service"`
}
