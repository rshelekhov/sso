package app

import (
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/domain/service/verification"
	"github.com/rshelekhov/sso/internal/domain/usecase/app"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	appDB "github.com/rshelekhov/sso/internal/infrastructure/storage/app"
	authDB "github.com/rshelekhov/sso/internal/infrastructure/storage/auth"
	sessionDB "github.com/rshelekhov/sso/internal/infrastructure/storage/session"
	userDB "github.com/rshelekhov/sso/internal/infrastructure/storage/user"
	verificationDB "github.com/rshelekhov/sso/internal/infrastructure/storage/verification"
	"github.com/rshelekhov/sso/pkg/middleware/appid"
	"github.com/rshelekhov/sso/pkg/middleware/requestid"
	"log/slog"

	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger, cfg *config.ServerSettings) *App {
	// Initialize main storage
	dbConn, err := newDBConnection(cfg.Storage)
	if err != nil {
		log.Error("failed to init database connection", slog.Any("error", err))
	}

	// Initialize storages
	appStorage, err := appDB.NewStorage(dbConn)
	if err != nil {
		log.Error("failed to init app storage", slog.Any("error", err))
	}

	authStorage, err := authDB.NewStorage(dbConn)
	if err != nil {
		log.Error("failed to init auth storage", slog.Any("error", err))
	}

	sessionStorage, err := sessionDB.NewStorage(dbConn)
	if err != nil {
		log.Error("failed to init session storage", slog.Any("error", err))
	}

	userStorage, err := userDB.NewStorage(dbConn)
	if err != nil {
		log.Error("failed to init user storage", slog.Any("error", err))
	}

	verificationStorage, err := verificationDB.NewStorage(dbConn)
	if err != nil {
		log.Error("failed to init verification storage", slog.Any("error", err))
	}

	keyStorage, err := newKeyStorage(cfg.KeyStorage)
	if err != nil {
		log.Error("failed to init key storage", slog.Any("error", err))
	}

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
	userDataService := userdata.NewService(userStorage)
	verificationService := verification.NewService(cfg.VerificationService.TokenExpiryTime, verificationStorage)

	// Initialize usecases
	appUsecase := app.NewUsecase(log, tokenService, appStorage)

	authUsecases := auth.NewUsecase(
		log,
		sessionService,
		userDataService,
		mailService,
		tokenService,
		verificationService,
		authStorage,
	)

	userUsecase := user.NewUsecase(
		log,
		requestIDManager,
		appIDManager,
		appValidator,
		sessionService,
		userDataService,
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
