package app

import (
	"fmt"
	"log/slog"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"

	httpapp "github.com/rshelekhov/sso/internal/app/http"

	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
)

type App struct {
	GRPCServer *grpcapp.App
	HTTPServer *httpapp.App
	dbConn     *storage.DBConnection
}

func New(log *slog.Logger, cfg *config.ServerSettings) (*App, error) {
	builder := newBuilder(log, cfg)
	return builder.Build()
}

func (a *App) Stop() error {
	const method = "app.Stop"

	// Shutdown gRPC server
	a.GRPCServer.Stop()

	// Shutdown HTTP server
	if err := a.HTTPServer.Stop(); err != nil {
		return fmt.Errorf("%s:failed to stop http server: %w", method, err)
	}

	// Close database connection
	if err := a.dbConn.Close(); err != nil {
		return fmt.Errorf("%s:failed to close database connection: %w", method, err)
	}

	return nil
}
