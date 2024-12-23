package app

import (
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/pkg/middleware/appid"
	"github.com/rshelekhov/sso/pkg/middleware/requestid"
	"github.com/rshelekhov/sso/pkg/storage/postgres"
	"github.com/rshelekhov/sso/src/config/settings"
	"github.com/rshelekhov/sso/src/domain/service/appvalidator"
	"github.com/rshelekhov/sso/src/domain/service/session"
	"github.com/rshelekhov/sso/src/domain/service/token"
	"github.com/rshelekhov/sso/src/domain/service/user"
	"github.com/rshelekhov/sso/src/domain/service/verification"
	"github.com/rshelekhov/sso/src/domain/usecase"
	"github.com/rshelekhov/sso/src/infrastructure/service/mail"
	postgres3 "github.com/rshelekhov/sso/src/infrastructure/storage/app/postgres"
	postgres2 "github.com/rshelekhov/sso/src/infrastructure/storage/auth/postgres"
	"github.com/rshelekhov/sso/src/infrastructure/storage/key"
	postgres4 "github.com/rshelekhov/sso/src/infrastructure/storage/session/postgres"
	postgres5 "github.com/rshelekhov/sso/src/infrastructure/storage/user/postgres"
	postgres6 "github.com/rshelekhov/sso/src/infrastructure/storage/verification/postgres"
	"log/slog"

	grpcapp "github.com/rshelekhov/sso/src/app/grpc"
	"github.com/rshelekhov/sso/src/config"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger, cfg *config.ServerSettings) *App {
	// Initialize storages
	pg, err := postgres.New(cfg)
	if err != nil {
		log.Error("failed to init storage", slog.Any("error", err))
	}

	log.Debug("storage initiated")

	// Initialize storages
	appStorage := postgres3.NewAppStorage(pg)
	authStorage := postgres2.NewAuthStorage(pg)
	sessionStorage := postgres4.NewSessionStorage(pg)
	userStorage := postgres5.NewUserStorage(pg)
	verificationStorage := postgres6.NewVerificationStorage(pg)

	keyStorage, err := newKeyStorage(cfg.KeyStorage)
	if err != nil {
		log.Error("failed to init key storage", slog.Any("error", err))
	}

	log.Debug("key storage initiated")

	mailService, err := newMailService(cfg.MailService)
	if err != nil {
		log.Error("failed to init mail session", slog.Any("error", err))
	}

	// Initialize requestID manager
	requestIDManager := requestid.NewManager()

	// Initialize appID manager
	appIDManager := appid.NewManager()

	// Initialize JWT manager
	jwtManager := jwtauth.NewManager(cfg.JWT.JWKSURL)

	// Initialize domain services
	appValidator := appvalidator.NewService(appStorage)

	tokenService, err := newTokenService(cfg.JWT, cfg.PasswordHash, keyStorage)
	if err != nil {
		log.Error("failed to init token service", slog.Any("error", err))
	}

	sessionService := session.NewService(tokenService, sessionStorage)
	userService := user.NewService(userStorage)
	verificationService := verification.NewService(cfg.VerificationService.TokenExpiryTime, verificationStorage)

	// Initialize usecases
	appUsecase := usecase.NewAppUsecase(log, tokenService, appStorage)

	authUsecases := usecase.NewAuthUsecase(
		log,
		sessionService,
		userService,
		mailService,
		tokenService,
		verificationService,
		authStorage,
	)

	userUsecase := usecase.NewUserUsecase(
		log,
		requestIDManager,
		appIDManager,
		appValidator,
		sessionService,
		userService,
		tokenService,
		tokenService,
	)

	// App
	grpcServer := grpcapp.New(
		log,
		requestIDManager,
		appIDManager,
		appValidator,
		jwtManager,
		appUsecase,
		authUsecases,
		userUsecase,
		cfg.GRPCServer.Port,
	)

	return &App{
		GRPCServer: grpcServer,
	}
}

func newKeyStorage(cfg settings.KeyStorage) (token.KeyStorage, error) {
	keysConfig, err := settings.ToKeysConfig(cfg)
	if err != nil {
		return nil, err
	}

	keyStorage, err := key.NewStorage(keysConfig)
	if err != nil {
		return nil, err
	}

	return keyStorage, nil
}

func newMailService(cfg settings.MailService) (*mail.Service, error) {
	mailConfig, err := settings.ToMailConfig(cfg)
	if err != nil {
		return nil, err
	}

	return mail.NewService(mailConfig), nil
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
