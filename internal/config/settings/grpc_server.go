package settings

import "time"

type GRPCServer struct {
	Host         string        `yaml:"Host" default:"localhost"`
	Port         string        `yaml:"Port" default:"44044"`
	Timeout      time.Duration `yaml:"Timeout"`
	RetriesCount int           `yaml:"RetriesCount" default:"3"`
}
