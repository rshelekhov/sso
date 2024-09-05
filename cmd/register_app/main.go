package main

//
// A small CLI utility for registering app in SSO
//

import (
	"context"
	"flag"

	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/storage"
	"github.com/rshelekhov/sso/internal/storage/postgres"
	"github.com/rshelekhov/sso/internal/usecase"
)

func main() {
	var appName string

	flag.StringVar(&appName, "name", appName, "Name of the app")
	flag.StringVar(&appName, "n", appName, "Name of the app")

	cfg := config.MustLoad()

	log := logger.SetupLogger(cfg.AppEnv)
	if appName == "" {
		// I'm fine with panic for now, as it's an auxiliary utility.
		panic("app name is required")
	}

	pg, err := postgres.NewStorage(cfg)
	if err != nil {
		log.Error("failed to init storage", logger.Err(err))
	}

	appStorage := postgres.NewAppStorage(pg)

	keyStorage, err := storage.NewKeyStorage(cfg.KeyStorage)
	if err != nil {
		log.Error("failed to init key storage", logger.Err(err))
	}

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

	appUsecase := usecase.NewAppUsecase(log, appStorage, tokenService)

	err = appUsecase.RegisterApp(context.Background(), appName)
	if err != nil {
		return
	}
}
