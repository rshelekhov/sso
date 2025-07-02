package main

//
// A small CLI utility for registering app in SSO
//

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/rshelekhov/golib/config"
	appConfig "github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/domain/usecase/client"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	appDB "github.com/rshelekhov/sso/internal/infrastructure/storage/client"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/key"
)

func main() {
	var appName string

	flag.StringVar(&appName, "name", appName, "Name of the app")
	flag.StringVar(&appName, "n", appName, "Name of the app")
	flag.Parse()

	cfg := config.MustLoad[appConfig.ServerSettings](
		config.WithSkipFlags(true),
	)

	log := slog.New(slog.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	})))

	if appName == "" {
		// I'm fine with panic for now, as it's an auxiliary utility.
		panic("app name is required")
	}

	dbConn, err := newDBConnection(cfg.Storage)
	if err != nil {
		log.Error("failed to init database connection", slog.Any("error", err))
	}

	appStorage, err := appDB.NewStorage(dbConn)
	if err != nil {
		log.Error("failed to init app storage", slog.Any("error", err))
	}

	keyStorage, err := newKeyStorage(cfg.KeyStorage)
	if err != nil {
		log.Error("failed to init key storage", slog.Any("error", err))
	}

	tokenService, err := newTokenService(cfg.JWT, cfg.PasswordHash, keyStorage)
	if err != nil {
		log.Error("failed to init token service", slog.Any("error", err))
	}

	clientUsecase := client.NewUsecase(log, tokenService, appStorage)

	err = clientUsecase.RegisterClient(context.Background(), appName)
	if err != nil {
		return
	}
}

func newDBConnection(cfg settings.Storage) (*storage.DBConnection, error) {
	storageConfig, err := settings.ToStorageConfig(cfg)
	if err != nil {
		return nil, err
	}

	dbConnection, err := storage.NewDBConnection(storageConfig)
	if err != nil {
		return nil, err
	}

	return dbConnection, nil
}

func newKeyStorage(cfg settings.KeyStorage) (token.KeyStorage, error) {
	keyStorageConfig, err := settings.ToKeyStorageConfig(cfg)
	if err != nil {
		return nil, err
	}

	keyStorage, err := key.NewStorage(keyStorageConfig)
	if err != nil {
		return nil, err
	}

	return keyStorage, nil
}

func newTokenService(jwt settings.JWT, passwordHash settings.PasswordHashParams, keyStorage token.KeyStorage) (*token.Service, error) {
	jwtConfig, err := settings.ToJWTConfig(jwt)
	if err != nil {
		return nil, err
	}

	passwordHashConfig, err := settings.ToPasswordHashConfig(passwordHash)
	if err != nil {
		return nil, err
	}

	tokenService := token.NewService(token.Config{
		JWT:                jwtConfig,
		PasswordHashParams: passwordHashConfig,
	},
		keyStorage,
	)

	return tokenService, nil
}
