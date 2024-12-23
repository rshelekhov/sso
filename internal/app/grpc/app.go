package grpcapp

import (
	"context"
	"fmt"
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/pkg/middleware"
	"github.com/rshelekhov/sso/src/domain/service/appvalidator"
	"github.com/rshelekhov/sso/src/domain/usecase"
	"log/slog"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	authgrpc "github.com/rshelekhov/sso/src/controller/grpc"
	"github.com/rshelekhov/sso/src/lib/grpc/interceptor/localerror"
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
	log *slog.Logger,
	requestIDMgr middleware.Manager,
	appIDMgr middleware.Manager,
	appValidator appvalidator.Validator,
	jwtMiddleware jwtauth.Middleware,
	appUsecase usecase.AppProvider,
	authUsecase usecase.AuthProvider,
	userUsecase usecase.UserProvider,
	port string,
) *App {
	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(
			// logging.StartCall, logging.FinishCall,
			logging.PayloadReceived, logging.PayloadSent,
		),
		// Add any other option (check functions starting with logging.With).
	}

	recoveryOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			log.Error("Recovered from panic", slog.Any("panic", p))

			return status.Errorf(codes.Internal, "internal error")
		}),
	}

	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recovery.UnaryServerInterceptor(recoveryOpts...),
			logging.UnaryServerInterceptor(InterceptorLogger(log), loggingOpts...),
			requestIDMgr.UnaryServerInterceptor(),
			appIDMgr.UnaryServerInterceptor(),
			jwtMiddleware.UnaryServerInterceptor(),
			localerror.UnaryServerInterceptor(),
		),
	)

	// Auth grpc
	authgrpc.RegisterController(
		gRPCServer,
		log,
		requestIDMgr,
		appIDMgr,
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
	const method = "grpcapp.App.Run"

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
	const method = "grpcapp.App.Stop"

	a.log.With(slog.String("method", method)).Info("stopping gRPC server")

	a.gRPCServer.GracefulStop()
}
