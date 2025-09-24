package main

//
// A small CLI utility for registering app in SSO
//

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/rshelekhov/golib/config"
	appConfig "github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/domain/usecase/client"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	appDB "github.com/rshelekhov/sso/internal/infrastructure/storage/client"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/key"
	"github.com/rshelekhov/sso/internal/observability/metrics"
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

	// Use no-op recorder for CLI utility to avoid metrics overhead
	recorder := &metrics.NoOpRecorder{}

	dbConn, err := newDBConnection(cfg.Storage, recorder)
	if err != nil {
		log.Error("failed to init database connection", slog.Any("error", err))
	}

	appStorage, err := appDB.NewStorage(dbConn, recorder)
	if err != nil {
		log.Error("failed to init app storage", slog.Any("error", err))
	}

	keyStorage, err := newKeyStorage(cfg.KeyStorage, recorder)
	if err != nil {
		log.Error("failed to init key storage", slog.Any("error", err))
	}

	tokenService, err := newTokenService(cfg.JWT, cfg.PasswordHash, keyStorage)
	if err != nil {
		log.Error("failed to init token service", slog.Any("error", err))
	}

	clientUsecase := client.NewUsecase(log, tokenService, appStorage, nil)

	err = clientUsecase.RegisterClient(context.Background(), appName)
	if err != nil {
		return
	}
}

func newDBConnection(cfg settings.Storage, recorder metrics.MetricsRecorder) (*storage.DBConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbConnection, err := storage.NewDBConnection(ctx, cfg, recorder)
	if err != nil {
		return nil, err
	}

	return dbConnection, nil
}

func newKeyStorage(cfg settings.KeyStorage, recorder metrics.MetricsRecorder) (token.KeyStorage, error) {
	keyStorageConfig, err := settings.ToKeyStorageConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyStorage, err := key.NewStorage(ctx, keyStorageConfig, recorder)
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
		nil,
	)

	return tokenService, nil
}
