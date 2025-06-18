package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/redis/go-redis/v9"
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/internal/config"
	ssogrpc "github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	authenticate "github.com/rshelekhov/sso/internal/lib/interceptor/auth"
	"github.com/rshelekhov/sso/internal/lib/interceptor/requestid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       string
}

func New(
	port string,
	log *slog.Logger,
	jwtMiddleware jwtauth.Middleware,
	appValidator appvalidator.Validator,
	appUsecase ssogrpc.AppUsecase,
	authUsecase ssogrpc.AuthUsecase,
	userUsecase ssogrpc.UserUsecase,
	redisClient *redis.Client,
	methodsConfig *config.GRPCMethodsConfig,
) *App {
	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(
			logging.PayloadReceived, logging.PayloadSent,
		),
	}

	recoveryOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			log.Error("Recovered from panic", slog.Any("panic", p))
			return status.Errorf(codes.Internal, "internal error")
		}),
	}

	requestIDInterceptor := requestid.NewInterceptor()
	appIDInterceptor := appid.NewInterceptor(methodsConfig)

	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryOpts...),
			logging.UnaryServerInterceptor(InterceptorLogger(log), loggingOpts...),
			requestIDInterceptor.UnaryServerInterceptor(),
			appIDInterceptor.UnaryServerInterceptor(),
			authenticate.UnaryServerInterceptor(methodsConfig, jwtMiddleware.UnaryServerInterceptor()),
		),
	)

	ssogrpc.RegisterController(
		gRPCServer,
		log,
		appValidator,
		appUsecase,
		authUsecase,
		userUsecase,
	)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const method = "grpc.App.Run"

	log := a.log.With(
		slog.String("method", method),
		slog.String("port", a.port),
	)

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", a.port))
	if err != nil {
		return fmt.Errorf("%s: failed to listen gRPC port: %w", method, err)
	}

	log.Info("gRPC server is running", slog.String("addr", l.Addr().String()))

	if err = a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: failed to serve gRPC server: %w", method, err)
	}

	return nil
}

func (a *App) Stop() {
	const method = "grpc.App.Stop"

	a.log.With(slog.String("method", method)).Info("stopping gRPC server")

	a.gRPCServer.GracefulStop()
}
