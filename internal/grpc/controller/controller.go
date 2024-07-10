package controller

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/port"
	"google.golang.org/grpc"
	"log/slog"
)

type controller struct {
	ssov1.UnimplementedAuthServer
	log         *slog.Logger
	appUsecase  port.AppUsecase
	authUsecase port.AuthUsecase
}

func RegisterController(gRPC *grpc.Server, log *slog.Logger, appUsecase port.AppUsecase, authUsecase port.AuthUsecase) {
	ssov1.RegisterAuthServer(gRPC, &controller{
		log:         log,
		appUsecase:  appUsecase,
		authUsecase: authUsecase,
	})
}
