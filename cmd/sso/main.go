package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rshelekhov/golib/config"
	"github.com/rshelekhov/golib/observability"
	"github.com/rshelekhov/sso/internal/app"
	appConfig "github.com/rshelekhov/sso/internal/config"
)

func main() {
	cfg := config.MustLoad[appConfig.ServerSettings]()

	obsCfg, err := observability.NewConfig(
		observability.ConfigParams{
			Env:            cfg.App.Env,
			ServiceName:    cfg.App.ServiceName,
			ServiceVersion: cfg.App.ServiceVersion,
			EnableMetrics:  cfg.App.EnableMetrics,
			OTLPEndpoint:   cfg.App.OTLPEndpoint,
		})
	if err != nil {
		slog.Error("failed to create observability config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	obs, err := observability.Init(context.Background(), obsCfg)
	if err != nil {
		slog.Error("failed to init observability", slog.String("error", err.Error()))
		os.Exit(1)
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := obs.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown observability", slog.String("error", err.Error()))
		}
	}()

	log := obs.Logger.With(slog.String("env", cfg.App.Env))

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
