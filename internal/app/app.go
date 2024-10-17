package app

import (
	"context"
	"log/slog"

	"github.com/rshelekhov/sso/internal/app/gateway"

	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/service/mail"
	"github.com/rshelekhov/sso/internal/storage"
	"github.com/rshelekhov/sso/internal/storage/postgres"
	"github.com/rshelekhov/sso/internal/usecase"
)

type App struct {
	GRPCServer *grpcapp.App
	HTTPServer *gateway.App
}

func New(ctx context.Context, log *slog.Logger, cfg *config.ServerSettings) *App {
	// Initialize storages
	pg, err := postgres.NewStorage(cfg)
	if err != nil {
		log.Error("failed to init storage", logger.Err(err))
	}

	log.Debug("storage initiated")

	appStorage := postgres.NewAppStorage(pg)
	authStorage := postgres.NewAuthStorage(pg)

	keyStorage, err := storage.NewKeyStorage(cfg.KeyStorage)
	if err != nil {
		log.Error("failed to init key storage", logger.Err(err))
	}

	log.Debug("key storage initiated")

	mailService := mail.NewMailService(cfg.MailService)

	// Initialize token service
	tokenService := jwtoken.NewService(
		cfg.JWTAuth.Issuer,
		cfg.JWTAuth.SigningMethod,
		keyStorage,
		cfg.PasswordHash,
		cfg.JWTAuth.JWKSetTTL,
		cfg.JWTAuth.AccessTokenTTL,
		cfg.JWTAuth.RefreshTokenTTL,
		cfg.JWTAuth.RefreshTokenCookieDomain,
		cfg.JWTAuth.RefreshTokenCookiePath,
	)

	// Initialize usecases
	appUsecase := usecase.NewAppUsecase(log, appStorage, tokenService)
	authUsecases := usecase.NewAuthUsecase(log, authStorage, tokenService, mailService)

	// App
	grpcServer := grpcapp.New(log, appUsecase, authUsecases, cfg.GRPCServer.Port)

	// Gateway
	httpServer := gateway.New(ctx, log, cfg.GRPCServer, cfg.HTTPServer)

	return &App{
		GRPCServer: grpcServer,
		HTTPServer: httpServer,
	}
}
