package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rshelekhov/sso/internal/app"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/logger"
)

func main() {
	cfg := config.MustLoad()

	log := logger.SetupLogger(cfg.AppEnv)

	// A field with information about the current environment
	// will be added to each message
	log = log.With(slog.String("env", cfg.AppEnv))

	log.Info("starting application")
	log.Debug("logger debug mode enabled")

	application, err := app.New(log, cfg)
	if err != nil {
		log.Error("failed to initialize application", slog.String("error", err.Error()))
		os.Exit(1)
	}

	go func() {
		application.GRPCServer.MustRun()
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("shutting down...", slog.String("signal", sign.String()))

	if err := application.Stop(); err != nil {
		log.Error("failed to stop application", slog.String("error", err.Error()))
		os.Exit(1)
	}

	log.Info("graceful shutdown completed")
}
