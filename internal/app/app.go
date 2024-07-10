package app

import (
	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/storage/postgres"
	"github.com/rshelekhov/sso/internal/usecase"
	"log/slog"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger, cfg *config.ServerSettings, tokenAuth *jwtoken.Service) *App {
	// Storage
	pg, err := postgres.NewStorage(cfg)
	if err != nil {
		log.Error("failed to init storage", logger.Err(err))
	}

	log.Debug("storage initiated")

	appStorage := postgres.NewAppStorage(pg)
	authStorage := postgres.NewAuthStorage(pg)

	// Usecases
	appUsecase := usecase.NewAppUsecase(log, appStorage, cfg)
	authUsecases := usecase.NewAuthUsecase(log, authStorage, tokenAuth)

	// App
	grpcApp := grpcapp.New(log, appUsecase, authUsecases, cfg.GRPCServer.Port)

	return &App{
		GRPCServer: grpcApp,
	}
}
