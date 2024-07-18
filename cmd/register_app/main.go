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
	"os"
)

func main() {
	var appName string
	flag.StringVar(&appName, "name", appName, "Name of the app")
	flag.StringVar(&appName, "n", appName, "Name of the app")
	flag.Parse()

	if appName == "" {
		// I'm fine with panic for now, as it's an auxiliary utility.
		panic("app name is required")
	}

	cfg := config.MustLoadPath(configPath())

	log := logger.SetupLogger(cfg.AppEnv)

	pg, err := postgres.NewStorage(cfg)
	if err != nil {
		log.Error("failed to init storage: ", err)
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
		cfg.JWTAuth.JWKSetTTL,
		cfg.JWTAuth.AccessTokenTTL,
		cfg.JWTAuth.RefreshTokenTTL,
		cfg.JWTAuth.RefreshTokenCookieDomain,
		cfg.JWTAuth.RefreshTokenCookiePath,
		cfg.DefaultHashBcrypt.Cost,
		cfg.DefaultHashBcrypt.Salt,
	)

	appUsecase := usecase.NewAppUsecase(cfg, log, appStorage, tokenService)

	err = appUsecase.RegisterApp(context.Background(), appName)
	if err != nil {
		return
	}
}

const (
	CONFIG_PATH       = "CONFIG_PATH"
	defaultConfigPath = "./config/.env"
)

func configPath() string {
	if v := os.Getenv(CONFIG_PATH); v != "" {
		return v
	}

	return defaultConfigPath
}
