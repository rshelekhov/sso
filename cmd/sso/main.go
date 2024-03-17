package main

import (
	"github.com/rshelekhov/sso/config"
	"github.com/rshelekhov/sso/internal/app"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
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

	go application.GRPCServer.MustRun()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("shutting down...", slog.String("signal", sign.String()))

	application.GRPCServer.Stop()
	log.Info("graceful shutdown completed")
}
