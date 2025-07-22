package settings

type App struct {
	Env               string `yaml:"Env"`
	ServiceName       string `yaml:"ServiceName"`
	ServiceVersion    string `yaml:"ServiceVersion"`
	EnableMetrics     bool   `yaml:"EnableMetrics"`
	OTLPEndpoint      string `yaml:"OTLPEndpoint"`
	OTLPTransportType string `yaml:"OTLPTransportType"`
}
