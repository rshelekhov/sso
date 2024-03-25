package app

import (
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/config"
	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/storage/postgres"
	"github.com/rshelekhov/sso/internal/usecase"
	"log/slog"
)

type App struct {
	GRPCServer *grpcapp.App
}

// TODO: refactor it to use jwtoken which I used in Reframed
func New(log *slog.Logger, cfg *config.ServerSettings, tokenAuth *jwtauth.TokenService) *App {

	// Auth storage
	pg, err := postgres.NewStorage(cfg)
	if err != nil {
		log.Error("failed to init storage", logger.Err(err))
	}

	log.Debug("storage initiated")

	authStorage := postgres.NewAuthStorage(pg)

	// Auth usecases
	authUsecases := usecase.NewAuthUsecase(log, authStorage, tokenAuth)

	// App
	grpcApp := grpcapp.New(log, authUsecases, cfg.GRPCServer.Port)

	return &App{
		GRPCServer: grpcApp,
	}
}
