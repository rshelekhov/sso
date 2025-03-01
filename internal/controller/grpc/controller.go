package grpc

import (
	"context"
	"log/slog"

	"github.com/rshelekhov/sso/internal/domain/entity"

	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
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
	appUsecase   AppUsecase
	authUsecase  AuthUsecase
	userUsecase  UserUsecase
}

type (
	AppUsecase interface {
		RegisterApp(ctx context.Context, appName string) error
		DeleteApp(ctx context.Context, appID, secretHash string) error
	}

	AuthUsecase interface {
		Login(ctx context.Context, appID string, reqData *entity.UserRequestData) (entity.SessionTokens, error)
		RegisterUser(ctx context.Context, appID string, reqData *entity.UserRequestData, confirmEmailEndpoint string) (entity.SessionTokens, error)
		VerifyEmail(ctx context.Context, verificationToken string) (entity.VerificationResult, error)
		ResetPassword(ctx context.Context, appID string, reqData *entity.ResetPasswordRequestData, changePasswordEndpoint string) error
		ChangePassword(ctx context.Context, appID string, reqData *entity.ChangePasswordRequestData) (entity.ChangingPasswordResult, error)
		LogoutUser(ctx context.Context, appID string, reqData *entity.UserDeviceRequestData) error
		RefreshTokens(ctx context.Context, appID string, reqData *entity.RefreshTokenRequestData) (entity.SessionTokens, error)
		GetJWKS(ctx context.Context, appID string) (entity.JWKS, error)
	}

	UserUsecase interface {
		GetUserByID(ctx context.Context, appID string) (entity.User, error)
		UpdateUser(ctx context.Context, appID string, data entity.UserRequestData) (entity.User, error)
		DeleteUser(ctx context.Context, appID string) error
	}
)

func RegisterController(
	gRPC *grpc.Server,
	log *slog.Logger,
	requestIDMgr middleware.ContextManager,
	appIDMgr middleware.ContextManager,
	appValidator appvalidator.Validator,
	appUsecase AppUsecase,
	authUsecase AuthUsecase,
	userUsecase UserUsecase,
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
