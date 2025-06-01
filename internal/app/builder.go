package app

import (
	"fmt"
	"log/slog"

	jwksadapter "github.com/rshelekhov/sso/internal/adapter"
	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/service/rbac"
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
	rbacDB "github.com/rshelekhov/sso/internal/infrastructure/storage/rbac"
	sessionDB "github.com/rshelekhov/sso/internal/infrastructure/storage/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	userDB "github.com/rshelekhov/sso/internal/infrastructure/storage/user"
	verificationDB "github.com/rshelekhov/sso/internal/infrastructure/storage/verification"
	"github.com/rshelekhov/sso/pkg/jwtauth"
)

type Builder struct {
	logger *slog.Logger
	cfg    *config.ServerSettings

	storages   *Storages
	managers   *Managers
	services   *Services
	usecases   *Usecases
	configs    *Configs
	grpcServer *grpcapp.App
}

type Storages struct {
	dbConn       *storage.DBConnection
	redisConn    *storage.RedisConnection
	trMgr        transaction.Manager
	app          appDB.Storage
	rbac         rbac.Storage
	auth         auth.Storage
	session      session.SessionStorage
	device       session.DeviceStorage
	user         userdata.Storage
	verification verification.Storage
	key          token.KeyStorage
}

type Managers struct {
	jwt jwtauth.Manager
}

type Services struct {
	appValidator *appvalidator.AppValidator
	rbac         *rbac.Service
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

type Configs struct {
	gRPCMethodsConfig *config.GRPCMethodsConfig
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

	b.storages.rbac, err = rbacDB.NewStorage(b.storages.dbConn)
	if err != nil {
		return fmt.Errorf("failed to init rbac storage: %w", err)
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
	b.services.rbac = rbac.NewService(b.storages.rbac)
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
		b.services.appValidator,
		b.services.rbac,
		b.services.session,
		b.services.user,
		b.services.token,
		b.services.token,
		b.services.verification,
		b.storages.trMgr,
	)
}

func (b *Builder) BuildGRPCServer() error {
	b.logger.Info("building gRPC server")

	// Initialize gRPC server
	grpcApp := grpcapp.New(
		b.cfg.GRPCServer.Port,
		b.logger,
		b.managers.jwt,
		b.services.appValidator,
		b.services.token,
		b.usecases.app,
		b.usecases.auth,
		b.usecases.user,
		b.storages.redisConn.Client,
		b.configs.gRPCMethodsConfig,
	)

	b.grpcServer = grpcApp

	return nil
}

func (b *Builder) Build() (*App, error) {
	if err := b.BuildStorages(); err != nil {
		return nil, err
	}

	if err := b.BuildServices(); err != nil {
		return nil, err
	}

	b.BuildUsecases()

	b.configs = &Configs{}
	b.configs.gRPCMethodsConfig = config.NewGRPCMethodsConfig()

	b.managers = &Managers{}
	jwksAdapter := jwksadapter.NewJWKSAdapter(b.usecases.auth)
	jwksProvider := jwtauth.NewLocalJWKSProvider(jwksAdapter)
	b.managers.jwt = jwtauth.NewManager(jwksProvider)

	err := b.BuildGRPCServer()
	if err != nil {
		return nil, err
	}

	return &App{
		GRPCServer: b.grpcServer,
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
