package main

import (
	"context"
	"fmt"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)

	go func() {
		log.Info("starting servers")
		if err := application.Run(ctx); err != nil {
			errChan <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var shutdownReason string
	select {
	case sig := <-sigCh:
		shutdownReason = fmt.Sprintf("signal %s", sig.String())
		log.Info("received signal, shutting down", slog.String("signal", sig.String()))
		cancel()
	case err := <-errChan:
		shutdownReason = fmt.Sprintf("application error: %v", err)
		log.Error("application error, shutting down", slog.String("error", err.Error()))
	case <-ctx.Done():
		shutdownReason = "context cancelled"
		log.Info("context cancelled, shutting down")
	}

	log.Info("cleaning up resources", slog.String("reason", shutdownReason))
	if err := application.Stop(); err != nil {
		log.Error("failed to stop application", slog.String("error", err.Error()))
		os.Exit(1)
	}

	log.Info("graceful shutdown completed")
}
