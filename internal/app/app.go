package app

import (
	"log/slog"

	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger, cfg *config.ServerSettings) (*App, error) {
	builder := newBuilder(log, cfg)
	return builder.Build()
}
