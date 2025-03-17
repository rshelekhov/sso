package app

import (
	"fmt"
	"log/slog"

	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type App struct {
	GRPCServer *grpcapp.App
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

	// Close database connection
	if err := a.dbConn.Close(); err != nil {
		return fmt.Errorf("%s:failed to close database connection: %w", method, err)
	}

	return nil
}
