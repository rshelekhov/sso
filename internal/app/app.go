package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rshelekhov/golib/server"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

type App struct {
	Server     *server.App
	SSOService *SSOService
	dbConn     *storage.DBConnection
}

func New(log *slog.Logger, cfg *config.ServerSettings, registry *metrics.Registry) (*App, error) {
	builder := newBuilder(log, cfg, registry)
	return builder.Build()
}

func (a *App) Run(ctx context.Context) error {
	return a.Server.Run(ctx, a.SSOService)
}

func (a *App) Stop(ctx context.Context) error {
	const method = "app.Stop"

	a.Server.Shutdown()

	if err := a.dbConn.Close(ctx); err != nil {
		return fmt.Errorf("%s:failed to close database connection: %w", method, err)
	}

	return nil
}
