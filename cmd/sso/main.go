package main

import (
	"github.com/rshelekhov/sso/config"
	"github.com/rshelekhov/sso/internal/app"
	"github.com/rshelekhov/sso/pkg/logger"
	"log/slog"
)

func main() {
	cfg := config.MustLoad()

	log := logger.SetupLogger(cfg.AppEnv)

	// A field with information about the current environment
	// will be added to each message
	log = log.With(slog.String("env", cfg.AppEnv))

	log.Info("starting application", slog.Any("config", cfg))
	log.Debug("logger debug mode enabled")

	// TODO: refactor it to use jwtoken which I used in Reframed
	application := app.New(log, cfg.GRPCServer.Port, cfg.JWTAuth.AccessTokenTTL)

	application.GRPCServer.MustRun()

	// TODO: start server
}
