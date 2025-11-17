package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rshelekhov/golib/middleware/logging"
	"github.com/rshelekhov/golib/middleware/recovery"
	"github.com/rshelekhov/golib/observability/tracing"
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
	"github.com/rshelekhov/sso/internal/observability/metrics"
	"github.com/rshelekhov/sso/pkg/jwtauth"
	"google.golang.org/grpc"
)

type Builder struct {
	logger          *slog.Logger
	cfg             *config.ServerSettings
	metricsRegistry *metrics.Registry
	recorder        *metrics.Recorder

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

func newBuilder(logger *slog.Logger, cfg *config.ServerSettings, registry *metrics.Registry) *Builder {
	// Ensure we always have a valid metrics registry
	if registry == nil {
		registry = metrics.NewNoOpRegistry()
	}
	return &Builder{
		logger:          logger,
		cfg:             cfg,
		metricsRegistry: registry,
	}
}

func (b *Builder) BuildRecorder() {
	b.recorder = metrics.NewRecorder(b.metricsRegistry)
}

// getMetricsRecorder returns a valid metrics recorder, falling back to NoOp if recorder is nil
func (b *Builder) getMetricsRecorder() metrics.MetricsRecorder {
	if b.recorder != nil {
		return b.recorder
	}
	return &metrics.NoOpRecorder{}
}

func (b *Builder) BuildStorages() error {
	b.storages = &Storages{}
	var err error

	b.storages.dbConn, err = newDBConnection(b.cfg.Storage, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to init database connection: %w", err)
	}

	b.storages.redisConn, err = newRedisConnection(b.cfg.Cache.Redis, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to create redis connection: %w", err)
	}

	b.storages.trMgr, err = transaction.NewManager(b.storages.dbConn)
	if err != nil {
		return fmt.Errorf("failed to init transaction manager: %w", err)
	}

	b.storages.client, err = clientDB.NewStorage(b.storages.dbConn, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to init client storage: %w", err)
	}

	b.storages.auth, err = authDB.NewStorage(b.storages.dbConn, b.storages.trMgr, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to init auth storage: %w", err)
	}

	b.storages.session, err = sessionDB.NewStorage(b.storages.redisConn)
	if err != nil {
		return fmt.Errorf("failed to init session storage: %w", err)
	}

	b.storages.device, err = deviceDB.NewStorage(b.storages.dbConn, b.storages.trMgr, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to init user device storage: %w", err)
	}

	b.storages.user, err = userDB.NewStorage(b.storages.dbConn, b.storages.trMgr, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to init user storage: %w", err)
	}

	b.storages.verification, err = verificationDB.NewStorage(b.storages.dbConn, b.storages.trMgr, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to init verification storage: %w", err)
	}

	b.storages.key, err = newKeyStorage(b.cfg.KeyStorage, b.getMetricsRecorder())
	if err != nil {
		return fmt.Errorf("failed to init key storage: %w", err)
	}

	return nil
}

func (b *Builder) BuildServices() error {
	b.services = &Services{}
	var err error

	b.services.clientValidator = clientvalidator.NewService(b.storages.client)

	tokenMetrics := b.metricsRegistry.Business.Token

	b.services.token, err = newTokenService(
		b.cfg.JWT,
		b.cfg.PasswordHash,
		b.storages.key,
		tokenMetrics,
	)
	if err != nil {
		return fmt.Errorf("failed to init token service: %w", err)
	}

	sessionMetrics := b.metricsRegistry.Business.Session

	b.services.session = session.NewService(
		b.services.token,
		b.storages.session,
		b.storages.device,
		sessionMetrics,
	)
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

	clientMetrics := b.metricsRegistry.Business.Client

	b.usecases.client = client.NewUsecase(
		b.logger,
		b.services.token,
		b.storages.client,
		clientMetrics,
	)

	authMetrics := b.metricsRegistry.Business.Auth
	authTokenMetrics := b.metricsRegistry.Business.Token

	b.usecases.auth = auth.NewUsecase(
		b.logger,
		b.services.session,
		b.services.user,
		b.services.mail,
		b.services.token,
		b.services.verification,
		b.storages.trMgr,
		b.storages.auth,
		authMetrics,
		authTokenMetrics,
	)

	userMetrics := b.metricsRegistry.Business.User

	b.usecases.user = user.NewUsecase(
		b.logger,
		b.services.clientValidator,
		b.services.session,
		b.services.user,
		b.services.token,
		b.services.token,
		b.services.verification,
		b.storages.trMgr,
		userMetrics,
	)
}

func (b *Builder) BuildSSOService() {
	grpcMetrics := b.metricsRegistry.Infrastructure.GRPCServer

	b.ssoService = NewSSOService(
		b.logger,
		b.managers.jwt,
		b.services.clientValidator,
		b.usecases.client,
		b.usecases.auth,
		b.usecases.user,
		b.storages.redisConn.Client,
		b.configs.gRPCMethodsConfig,
		grpcMetrics,
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

	jwtTokenMetrics := b.metricsRegistry.Business.Token

	b.managers.jwt = jwtauth.NewManager(
		jwksProvider,
		jwtauth.WithMetricsRecorder(jwtTokenMetrics),
	)

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

	httpPort := b.cfg.HTTPServer.Port
	if httpPort == "" {
		return nil, fmt.Errorf("HTTP port is not configured")
	}

	var httpPortInt int
	if _, err := fmt.Sscanf(httpPort, "%d", &httpPortInt); err != nil {
		return nil, fmt.Errorf("invalid HTTP port: %w", err)
	}

	interceptors := []grpc.UnaryServerInterceptor{
		logging.UnaryServerInterceptor(b.logger),
		recovery.UnaryServerInterceptor(b.logger),
	}

	interceptors = append(interceptors, b.ssoService.GetCustomInterceptors()...)

	statsHandler := tracing.GRPCServerStatsHandler()

	// Configure grpc-gateway to forward HTTP headers to gRPC metadata
	muxOpts := []runtime.ServeMuxOption{
		runtime.WithIncomingHeaderMatcher(func(key string) (string, bool) {
			switch key {
			case "X-Client-Id", "x-client-id":
				return "x-client-id", true // Forward as lowercase to gRPC metadata
			case "Authorization", "authorization":
				return "authorization", true
			default:
				return "", false
			}
		}),
	}

	app, err := server.NewApp(
		context.Background(),
		server.WithGRPCPort(port),
		server.WithHTTPPort(httpPortInt),
		server.WithLogger(b.logger),
		server.WithShutdownTimeout(10*time.Second),
		server.WithUnaryInterceptors(interceptors...),
		server.WithStatsHandler(statsHandler),
		server.WithMuxOptions(muxOpts...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create server app: %w", err)
	}

	return app, nil
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

func newRedisConnection(cfg settings.RedisParams, recorder metrics.MetricsRecorder) (*storage.RedisConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	redisConnection, err := storage.NewRedisConnection(ctx, cfg, recorder)
	if err != nil {
		return nil, err
	}

	return redisConnection, nil
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

func newTokenService(
	jwt settings.JWT,
	passwordHash settings.PasswordHashParams,
	keyStorage token.KeyStorage,
	metrics token.MetricsRecorder,
) (*token.Service, error) {
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
		metrics,
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
