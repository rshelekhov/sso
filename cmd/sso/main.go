package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rshelekhov/sso/internal/app"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/logger"
)

func main() {
	cfg := config.MustLoad()

	log := logger.SetupLogger(cfg.AppEnv)

	// A field with information about the current environment
	// will be added to each message
	log = log.With(slog.String(key.Env, cfg.AppEnv))

	log.Info("starting application")
	log.Debug("logger debug mode enabled")

	application := app.New(context.Background(), log, cfg)

	go func() {
		application.GRPCServer.MustRun()
	}()

	application.HTTPServer.Start()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("shutting down...", slog.String("signal", sign.String()))

	application.GRPCServer.Stop()
	log.Info("graceful shutdown completed")
}
