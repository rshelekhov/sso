package grpcmethods

type ServiceConfig struct {
	TokenRequiredMethods []string `yaml:"token_required_methods"`
	AppIDRequiredMethods []string `yaml:"app_id_required_methods"`
}

type Config struct {
	Service ServiceConfig `yaml:"service"`
}
