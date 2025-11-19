package settings

import "time"

type HTTPServer struct {
	Host    string        `yaml:"Host" default:"localhost"`
	Port    string        `yaml:"Port" default:"8080"`
	Timeout time.Duration `yaml:"Timeout"`
}
