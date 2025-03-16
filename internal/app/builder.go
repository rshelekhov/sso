package app

import (
	"fmt"
	"log/slog"

	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	httpapp "github.com/rshelekhov/sso/internal/app/http"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/grpcmethods"
	"github.com/rshelekhov/sso/internal/config/settings"
	v1 "github.com/rshelekhov/sso/internal/controller/http/v1"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/domain/service/verification"
	"github.com/rshelekhov/sso/internal/domain/usecase/app"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	"github.com/rshelekhov/sso/internal/infrastructure/service/mail"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	appDB "github.com/rshelekhov/sso/internal/infrastructure/storage/app"
	authDB "github.com/rshelekhov/sso/internal/infrastructure/storage/auth"
	deviceDB "github.com/rshelekhov/sso/internal/infrastructure/storage/device"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/key"
	sessionDB "github.com/rshelekhov/sso/internal/infrastructure/storage/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	userDB "github.com/rshelekhov/sso/internal/infrastructure/storage/user"
	verificationDB "github.com/rshelekhov/sso/internal/infrastructure/storage/verification"
	"github.com/rshelekhov/sso/pkg/jwtauth"
	"github.com/rshelekhov/sso/pkg/middleware"
	"github.com/rshelekhov/sso/pkg/middleware/appid"
	"github.com/rshelekhov/sso/pkg/middleware/requestid"
)

type Builder struct {
	logger *slog.Logger
	cfg    *config.ServerSettings

	storages *Storages
	managers *Managers
	services *Services
	usecases *Usecases
}

type Storages struct {
	dbConn       *storage.DBConnection
	redisConn    *storage.RedisConnection
	trMgr        transaction.Manager
	app          appDB.Storage
	auth         auth.Storage
	session      session.SessionStorage
	device       session.DeviceStorage
	user         userdata.Storage
	verification verification.Storage
	key          token.KeyStorage
}

type Managers struct {
	requestID    middleware.Manager
	appIDManager middleware.Manager
	jwt          jwtauth.Manager
}

type Services struct {
	appValidator *appvalidator.AppValidator
	token        *token.Service
	session      *session.Session
	user         *userdata.UserData
	verification *verification.Service
	mail         *mail.Service
}

type Usecases struct {
	app  *app.App
	auth *auth.Auth
	user *user.User
}

func newBuilder(logger *slog.Logger, cfg *config.ServerSettings) *Builder {
	return &Builder{
		logger: logger,
		cfg:    cfg,
	}
}

func (b *Builder) BuildStorages() error {
	b.storages = &Storages{}
	var err error

	b.storages.dbConn, err = newDBConnection(b.cfg.Storage)
	if err != nil {
		return fmt.Errorf("failed to init database connection: %w", err)
	}

	redisConn, err := newRedisConnection(b.cfg.Cache.Redis)
	if err != nil {
		return fmt.Errorf("failed to create redis connection: %w", err)
	}

	b.storages.redisConn = redisConn

	b.storages.trMgr, err = transaction.NewManager(b.storages.dbConn)
	if err != nil {
		return fmt.Errorf("failed to init transaction manager: %w", err)
	}

	b.storages.app, err = appDB.NewStorage(b.storages.dbConn)
	if err != nil {
		return fmt.Errorf("failed to init app storage: %w", err)
	}

	b.storages.auth, err = authDB.NewStorage(b.storages.dbConn, b.storages.trMgr)
	if err != nil {
		return fmt.Errorf("failed to init auth storage: %w", err)
	}

	b.storages.session, err = sessionDB.NewStorage(b.storages.redisConn)
	if err != nil {
		return fmt.Errorf("failed to init session storage: %w", err)
	}

	b.storages.device, err = deviceDB.NewStorage(b.storages.dbConn, b.storages.trMgr)
	if err != nil {
		return fmt.Errorf("failed to init user device storage: %w", err)
	}

	b.storages.user, err = userDB.NewStorage(b.storages.dbConn, b.storages.trMgr)
	if err != nil {
		return fmt.Errorf("failed to init user storage: %w", err)
	}

	b.storages.verification, err = verificationDB.NewStorage(b.storages.dbConn, b.storages.trMgr)
	if err != nil {
		return fmt.Errorf("failed to init verification storage: %w", err)
	}

	b.storages.key, err = newKeyStorage(b.cfg.KeyStorage)
	if err != nil {
		return fmt.Errorf("failed to init key storage: %w", err)
	}

	return nil
}

func (b *Builder) BuildManagers() {
	b.managers = &Managers{}

	b.managers.requestID = requestid.NewManager()
	b.managers.appIDManager = appid.NewManager()
	b.managers.jwt = jwtauth.NewManager(b.cfg.JWT.JWKSURL)
}

func (b *Builder) BuildServices() error {
	b.services = &Services{}
	var err error

	b.services.appValidator = appvalidator.NewService(b.storages.app)

	b.services.token, err = newTokenService(b.cfg.JWT, b.cfg.PasswordHash, b.storages.key)
	if err != nil {
		return fmt.Errorf("failed to init token service: %w", err)
	}

	b.services.session = session.NewService(b.services.token, b.storages.session, b.storages.device)
	b.services.user = userdata.NewService(b.storages.user)
	b.services.verification = verification.NewService(b.cfg.VerificationService.TokenExpiryTime, b.storages.verification)

	b.services.mail, err = newMailService(b.cfg.MailService)
	if err != nil {
		return fmt.Errorf("failed to init mail service: %w", err)
	}

	return nil
}

func (b *Builder) BuildUsecases() {
	b.usecases = &Usecases{}

	b.usecases.app = app.NewUsecase(
		b.logger,
		b.services.token,
		b.storages.app,
	)

	b.usecases.auth = auth.NewUsecase(
		b.logger,
		b.services.session,
		b.services.user,
		b.services.mail,
		b.services.token,
		b.services.verification,
		b.storages.trMgr,
		b.storages.auth,
	)

	b.usecases.user = user.NewUsecase(
		b.logger,
		b.managers.requestID,
		b.managers.appIDManager,
		b.services.appValidator,
		b.services.session,
		b.services.user,
		b.services.token,
		b.services.token,
		b.services.verification,
		b.storages.trMgr,
	)
}

func (b *Builder) BuildGRPCServer() (*grpcapp.App, error) {
	cfg, err := grpcmethods.Load(b.cfg.GRPCServer.GRPCMethodsConfigPath)
	if err != nil {
		return nil, err
	}

	grpcMethods, err := grpcmethods.New(cfg)
	if err != nil {
		return nil, err
	}

	grpcServer := grpcapp.New(
		b.cfg.GRPCServer.Port,
		grpcMethods,
		b.logger,
		b.managers.requestID,
		b.managers.appIDManager,
		b.managers.jwt,
		b.services.appValidator,
		b.usecases.app,
		b.usecases.auth,
		b.usecases.user,
	)

	return grpcServer, nil
}

func (b *Builder) BuildHTTPServer() *httpapp.App {
	router := v1.NewRouter(
		b.cfg.HTTPServer,
		b.logger,
		b.managers.requestID,
		b.managers.appIDManager,
		b.managers.jwt,
		b.services.appValidator,
		b.usecases.auth,
	)

	httpServer := httpapp.New(
		b.cfg.HTTPServer,
		b.logger,
		router,
	)

	return httpServer
}

func (b *Builder) Build() (*App, error) {
	if err := b.BuildStorages(); err != nil {
		return nil, err
	}

	b.BuildManagers()

	if err := b.BuildServices(); err != nil {
		return nil, err
	}

	b.BuildUsecases()

	grpcServer, err := b.BuildGRPCServer()
	if err != nil {
		return nil, err
	}

	httpServer := b.BuildHTTPServer()

	return &App{
		GRPCServer: grpcServer,
		HTTPServer: httpServer,
		dbConn:     b.storages.dbConn,
	}, nil
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

func newRedisConnection(cfg settings.RedisParams) (*storage.RedisConnection, error) {
	redisConfig := settings.ToRedisConfig(cfg)

	redisConnection, err := storage.NewRedisConnection(redisConfig)
	if err != nil {
		return nil, err
	}

	return redisConnection, nil
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

	tokenService := token.NewService(
		token.Config{
			JWT:                jwtConfig,
			PasswordHashParams: passwordHashConfig,
		},
		keyStorage,
	)

	return tokenService, nil
}

func newMailService(cfg settings.MailService) (*mail.Service, error) {
	mailConfig, err := settings.ToMailConfig(cfg)
	if err != nil {
		return nil, err
	}

	return mail.NewService(mailConfig), nil
}
