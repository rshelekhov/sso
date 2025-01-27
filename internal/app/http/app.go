package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rshelekhov/sso/internal/config/settings"
)

type App struct {
	log              *slog.Logger
	router           *chi.Mux
	address          string
	timeout          time.Duration
	idleTimeout      time.Duration
	requestLimitByIP int
}

func New(
	cfg settings.HTTPServer,
	log *slog.Logger,
	router *chi.Mux,
) *App {
	return &App{
		log:              log,
		router:           router,
		address:          cfg.Address,
		timeout:          cfg.Timeout,
		idleTimeout:      cfg.IdleTimeout,
		requestLimitByIP: cfg.RequestLimitByIP,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const method = "http.App.Run"

	log := a.log.With(
		slog.String("method", method),
		slog.String("address", a.address),
	)

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	srv := http.Server{
		Addr:         a.address,
		Handler:      a.router,
		ReadTimeout:  a.timeout,
		WriteTimeout: a.timeout,
		IdleTimeout:  a.idleTimeout,
	}

	shutdownComplete := handleShutdown(func() {
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("httpserver.Shutdown failed")
		}
	})

	log.Info("HTTP server is starting", slog.String("address", a.address))

	if err := srv.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
		<-shutdownComplete
	} else {
		return fmt.Errorf("%s: failed to start http server: %w", method, err)
	}

	log.Info("shutdown gracefully")

	return nil
}

func handleShutdown(onShutdownSignal func()) <-chan struct{} {
	shutdown := make(chan struct{})

	go func() {
		shutdownSignal := make(chan os.Signal, 1)
		signal.Notify(shutdownSignal, os.Interrupt, syscall.SIGTERM)

		<-shutdownSignal

		onShutdownSignal()
		close(shutdown)
	}()

	return shutdown
}
