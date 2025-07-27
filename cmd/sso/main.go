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
	"github.com/rshelekhov/sso/internal/config/settings"
)

func initObservability(cfg settings.App) (*slog.Logger, func(), error) {
	if !cfg.EnableMetrics {
		return slog.Default().With(slog.String("env", cfg.Env)), func() {}, nil
	}

	obsCfg, err := observability.NewConfig(
		observability.ConfigParams{
			Env:               cfg.Env,
			ServiceName:       cfg.ServiceName,
			ServiceVersion:    cfg.ServiceVersion,
			EnableMetrics:     cfg.EnableMetrics,
			OTLPEndpoint:      cfg.OTLPEndpoint,
			OTLPTransportType: cfg.OTLPTransportType,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create observability config: %w", err)
	}

	obs, err := observability.Init(context.Background(), obsCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init observability: %w", err)
	}

	shutdownFunc := func() {
		// Force flush before shutdown with shorter timeout
		if obs.TracerProvider != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := obs.TracerProvider.ForceFlush(ctx); err != nil {
				slog.Warn("failed to flush traces", slog.String("error", err.Error()))
			}
			cancel()
		}

		// Use shorter timeout for shutdown to avoid hanging
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := obs.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown observability", slog.String("error", err.Error()))
		}
	}

	return obs.Logger.With(slog.String("env", cfg.Env)), shutdownFunc, nil
}

func main() {
	cfg := config.MustLoad[appConfig.ServerSettings]()

	log, shutdownObs, err := initObservability(cfg.App)
	if err != nil {
		slog.Error("failed to initialize observability", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer shutdownObs()

	log.Info("starting application")
	log.Debug("logger debug mode enabled")

	application, err := app.New(log, cfg)
	if err != nil {
		log.Error("failed to initialize application", slog.String("error", err.Error()))
		return
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
		cancel()
	case <-ctx.Done():
		shutdownReason = "context cancelled"

		log.Info("context cancelled, shutting down")
	}

	log.Info("cleaning up resources", slog.String("reason", shutdownReason))

	// Use a fresh context for cleanup to avoid cancelled context issues
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()

	if err := application.Stop(stopCtx); err != nil {
		log.Error("failed to stop application", slog.String("error", err.Error()))
		return
	}

	log.Info("graceful shutdown completed")
}
