package app

import (
	grpcapp "github.com/rshelekhov/sso/internal/app/grpc"
	"github.com/rshelekhov/sso/internal/logger"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

// TODO: refactor it to use jwtoken which I used in Reframed
func New(log logger.Interface, grpcPort string, tokenTTL time.Duration) *App {
	// TODO: initialize storage

	// TODO: init auth service

	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}
