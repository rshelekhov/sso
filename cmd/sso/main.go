package main

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/config"
	"github.com/rshelekhov/sso/internal/app"
	"github.com/rshelekhov/sso/internal/lib/jwt/service"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg := config.MustLoad()

	log := logger.SetupLogger(cfg.AppEnv)

	// A field with information about the current environment
	// will be added to each message
	log = log.With(slog.String("env", cfg.AppEnv))

	log.Info("starting application")
	log.Debug("logger debug mode enabled")

	tokenAuth := service.NewJWTokenService(
		jwt.SigningMethodHS256,
		cfg.JWTAuth.AccessTokenTTL,
		cfg.JWTAuth.RefreshTokenTTL,
		cfg.JWTAuth.RefreshTokenCookieDomain,
		cfg.JWTAuth.RefreshTokenCookiePath,
		cfg.JWTAuth.PasswordHash.Cost,
		cfg.JWTAuth.PasswordHash.Salt,
	)

	application := app.New(log.Logger, cfg, tokenAuth)

	go func() {
		application.GRPCServer.MustRun()
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("shutting down...", slog.String("signal", sign.String()))

	application.GRPCServer.Stop()
	log.Info("graceful shutdown completed")
}
