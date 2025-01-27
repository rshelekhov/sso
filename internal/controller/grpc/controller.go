package grpc

import (
	"log/slog"

	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/usecase/app"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	"github.com/rshelekhov/sso/pkg/middleware"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"google.golang.org/grpc"
)

type gRPCController struct {
	ssov1.UnimplementedAuthServer
	log          *slog.Logger
	requestIDMgr middleware.ContextManager
	appIDMgr     middleware.ContextManager
	appValidator appvalidator.Validator
	appUsecase   app.Usecase
	authUsecase  auth.Usecase
	userUsecase  user.Usecase
}

func RegisterController(
	gRPC *grpc.Server,
	log *slog.Logger,
	requestIDMgr middleware.ContextManager,
	appIDMgr middleware.ContextManager,
	appValidator appvalidator.Validator,
	appUsecase app.Usecase,
	authUsecase auth.Usecase,
	userUsecase user.Usecase,
) {
	ssov1.RegisterAuthServer(gRPC, &gRPCController{
		log:          log,
		requestIDMgr: requestIDMgr,
		appIDMgr:     appIDMgr,
		appValidator: appValidator,
		appUsecase:   appUsecase,
		authUsecase:  authUsecase,
		userUsecase:  userUsecase,
	})
}
