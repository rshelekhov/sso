package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/rshelekhov/golib/server"
	jwksadapter "github.com/rshelekhov/sso/internal/adapter"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator"
	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/domain/service/verification"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/domain/usecase/client"
	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	"github.com/rshelekhov/sso/internal/infrastructure/service/mail"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	authDB "github.com/rshelekhov/sso/internal/infrastructure/storage/auth"
	clientDB "github.com/rshelekhov/sso/internal/infrastructure/storage/client"
	deviceDB "github.com/rshelekhov/sso/internal/infrastructure/storage/device"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/key"
	sessionDB "github.com/rshelekhov/sso/internal/infrastructure/storage/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	userDB "github.com/rshelekhov/sso/internal/infrastructure/storage/user"
	verificationDB "github.com/rshelekhov/sso/internal/infrastructure/storage/verification"
	"github.com/rshelekhov/sso/pkg/jwtauth"
	"google.golang.org/grpc"
)

type Builder struct {
	logger *slog.Logger
	cfg    *config.ServerSettings

	storages   *Storages
	managers   *Managers
	services   *Services
	usecases   *Usecases
	configs    *Configs
	ssoService *SSOService
}

type Storages struct {
	dbConn       *storage.DBConnection
	redisConn    *storage.RedisConnection
	trMgr        transaction.Manager
	client       clientDB.Storage
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
	clientValidator *clientvalidator.ClientValidator
	token           *token.Service
	session         *session.Session
	user            *userdata.UserData
	verification    *verification.Service
	mail            *mail.Service
}

type Usecases struct {
	client *client.Client
	auth   *auth.Auth
	user   *user.User
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

	b.storages.client, err = clientDB.NewStorage(b.storages.dbConn)
	if err != nil {
		return fmt.Errorf("failed to init client storage: %w", err)
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

	b.services.clientValidator = clientvalidator.NewService(b.storages.client)

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

	b.usecases.client = client.NewUsecase(
		b.logger,
		b.services.token,
		b.storages.client,
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
		b.services.clientValidator,
		b.services.session,
		b.services.user,
		b.services.token,
		b.services.token,
		b.services.verification,
		b.storages.trMgr,
	)
}

func (b *Builder) BuildSSOService() {
	b.ssoService = NewSSOService(
		b.logger,
		b.managers.jwt,
		b.services.clientValidator,
		b.usecases.client,
		b.usecases.auth,
		b.usecases.user,
		b.storages.redisConn.Client,
		b.configs.gRPCMethodsConfig,
	)
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

	b.BuildSSOService()

	serverApp, err := b.createServerApp()
	if err != nil {
		return nil, fmt.Errorf("failed to create server app: %w", err)
	}

	return &App{
		Server:     serverApp,
		SSOService: b.ssoService,
		dbConn:     b.storages.dbConn,
	}, nil
}

func (b *Builder) createServerApp() (*server.App, error) {
	grpcPort := b.cfg.GRPCServer.Port
	if grpcPort == "" {
		return nil, fmt.Errorf("gRPC port is not configured")
	}

	var port int
	if _, err := fmt.Sscanf(grpcPort, "%d", &port); err != nil {
		return nil, fmt.Errorf("invalid gRPC port: %w", err)
	}

	interceptors := []grpc.UnaryServerInterceptor{
		server.LoggingUnaryInterceptor(b.logger),
		server.RecoveryUnaryInterceptor(b.logger),
	}
	interceptors = append(interceptors, b.ssoService.GetCustomInterceptors()...)

	app, err := server.NewApp(
		context.Background(),
		server.WithGRPCPort(port),
		server.WithLogger(b.logger),
		server.WithShutdownTimeout(10*time.Second),
		server.WithUnaryInterceptors(interceptors...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create server app: %w", err)
	}

	return app, nil
}

func newDBConnection(cfg settings.Storage) (*storage.DBConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbConnection, err := storage.NewDBConnection(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return dbConnection, nil
}

func newRedisConnection(cfg settings.RedisParams) (*storage.RedisConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	redisConnection, err := storage.NewRedisConnection(ctx, cfg)
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
