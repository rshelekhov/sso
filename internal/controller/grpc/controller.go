package controller

import (
	"log/slog"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/port"
	"google.golang.org/grpc"
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
