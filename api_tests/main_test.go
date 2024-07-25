package cmd

import (
	"github.com/rshelekhov/sso/api_tests/mocks"
	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/storage"
	"github.com/rshelekhov/sso/internal/storage/postgres"
	"github.com/rshelekhov/sso/internal/usecase"
	"github.com/stretchr/testify/mock"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

const (
	configLocalTests = "../config/local_tests.env"
	templatesPath    = "./static/email_templates"
)

func TestMain(m *testing.M) {
	cfg := config.MustLoadPath(configLocalTests)

	log := logger.SetupLogger(cfg.AppEnv)

	log = log.With(slog.String(key.Env, cfg.AppEnv))

	log.Info("starting application")
	log.Debug("logger debug mode enabled")

	// ---

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

	// Create mocks
	mockMailService := mocks.NewMockMailService()

	// Set up the mock
	mockMailService.On("SendMessage", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMailService.On("SendHTML", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockMailService.On("GetTemplatesPath").Return(templatesPath)

	// Initialize token service
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

	// Initialize usecases
	appUsecase := usecase.NewAppUsecase(cfg, log, appStorage, tokenService)
	authUsecases := usecase.NewAuthUsecase(log, authStorage, tokenService, mockMailService)

	grpcApp := grpcapp.New(log, appUsecase, authUsecases, cfg.GRPCServer.Port)

	// Run test server
	go func() {
		grpcApp.MustRun()
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("shutting down...", slog.String("signal", sign.String()))

	grpcApp.Stop()
	log.Info("graceful shutdown completed")
}
