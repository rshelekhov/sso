package sso

import (
	"github.com/rshelekhov/sso/config"
	"github.com/rshelekhov/sso/pkg/logger"
)

func main() {
	cfg := config.MustLoad()

	log := logger.SetupLogger(cfg.AppEnv)

	// TODO: initialize app

	// TODO: start server
}
