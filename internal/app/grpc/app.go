package grpcapp

import (
	"fmt"
	authgrpc "github.com/rshelekhov/sso/internal/grpc/auth"
	"github.com/rshelekhov/sso/pkg/logger"
	"google.golang.org/grpc"
	"log/slog"
	"net"
)

type App struct {
	log        logger.Interface
	gRPCServer *grpc.Server
	port       string
}

func New(log logger.Interface, port string) *App {
	gRPCServer := grpc.NewServer()

	authgrpc.Register(gRPCServer)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.App.Run"

	log := a.log.With(
		slog.String("op", op),
		slog.String("port", a.port),
	)

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", a.port))
	if err != nil {
		return fmt.Errorf("%s: failed to listen gRPC port: %w", op, err)
	}

	log.Info("gRPC server is running", slog.String("addr", l.Addr().String()))

	if err = a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: failed to serve gRPC server: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.App.Stop"

	a.log.With(slog.String("op", op)).Info("stopping gRPC server")

	a.gRPCServer.GracefulStop()
}
