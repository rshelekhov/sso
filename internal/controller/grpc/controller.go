package grpc

import (
	"context"
	"log/slog"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"google.golang.org/grpc"
)

type gRPCController struct {
	ssov1.UnimplementedAuthServer
	log          *slog.Logger
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
		GetUser(ctx context.Context, appID string) (entity.User, error)
		GetUserByID(ctx context.Context, appID, userID string) (entity.User, error)
		UpdateUser(ctx context.Context, appID string, data entity.UserRequestData) (entity.User, error)
		GetUserRole(ctx context.Context, appID, userID string) (string, error)
		ChangeUserRole(ctx context.Context, appID, userID, role string) error
		DeleteUser(ctx context.Context, appID string) error
		DeleteUserByID(ctx context.Context, appID, userID string) error
	}
)

func RegisterController(
	gRPC *grpc.Server,
	log *slog.Logger,
	appValidator appvalidator.Validator,
	appUsecase AppUsecase,
	authUsecase AuthUsecase,
	userUsecase UserUsecase,
) {
	ssov1.RegisterAuthServer(gRPC, &gRPCController{
		log:          log,
		appValidator: appValidator,
		appUsecase:   appUsecase,
		authUsecase:  authUsecase,
		userUsecase:  userUsecase,
	})
}
