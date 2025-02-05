package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	server           *http.Server
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

	a.server = &http.Server{
		Addr:         a.address,
		Handler:      a.router,
		ReadTimeout:  a.timeout,
		WriteTimeout: a.timeout,
		IdleTimeout:  a.idleTimeout,
	}

	log.Info("HTTP server is starting", slog.String("address", a.address))

	if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s: failed to start http server: %w", method, err)
	}

	return nil
}

func (a *App) Stop() error {
	const method = "http.App.Stop"

	log := a.log.With(slog.String("method", method))
	log.Info("stopping HTTP server")

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	if err := a.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("%s: failed to shutdown http server: %w", method, err)
	}

	return nil
}
