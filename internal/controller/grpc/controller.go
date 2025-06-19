package grpc

import (
	"context"
	"log/slog"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator"
	"google.golang.org/grpc"
)

type gRPCController struct {
	ssov1.UnimplementedAuthServer
	log             *slog.Logger
	clientValidator clientvalidator.Validator
	clientUsecase   ClientUsecase
	authUsecase     AuthUsecase
	userUsecase     UserUsecase
}

type (
	ClientUsecase interface {
		RegisterClient(ctx context.Context, clientName string) error
		DeleteClient(ctx context.Context, clientID, secretHash string) error
	}

	AuthUsecase interface {
		Login(ctx context.Context, clientID string, reqData *entity.UserRequestData) (entity.SessionTokens, error)
		RegisterUser(ctx context.Context, clientID string, reqData *entity.UserRequestData, confirmEmailEndpoint string) (entity.SessionTokens, error)
		VerifyEmail(ctx context.Context, verificationToken string) (entity.VerificationResult, error)
		ResetPassword(ctx context.Context, clientID string, reqData *entity.ResetPasswordRequestData, changePasswordEndpoint string) error
		ChangePassword(ctx context.Context, clientID string, reqData *entity.ChangePasswordRequestData) (entity.ChangingPasswordResult, error)
		LogoutUser(ctx context.Context, clientID string, reqData *entity.UserDeviceRequestData) error
		RefreshTokens(ctx context.Context, clientID string, reqData *entity.RefreshTokenRequestData) (entity.SessionTokens, error)
		GetJWKS(ctx context.Context, clientID string) (entity.JWKS, error)
	}

	UserUsecase interface {
		GetUser(ctx context.Context, clientID string) (entity.User, error)
		GetUserByID(ctx context.Context, clientID, userID string) (entity.User, error)
		UpdateUser(ctx context.Context, clientID string, data entity.UserRequestData) (entity.User, error)
		DeleteUser(ctx context.Context, clientID string) error
		DeleteUserByID(ctx context.Context, clientID, userID string) error
	}
)

func RegisterController(
	gRPC *grpc.Server,
	log *slog.Logger,
	clientValidator clientvalidator.Validator,
	clientUsecase ClientUsecase,
	authUsecase AuthUsecase,
	userUsecase UserUsecase,
) {
	ssov1.RegisterAuthServer(gRPC, &gRPCController{
		log:             log,
		clientValidator: clientValidator,
		clientUsecase:   clientUsecase,
		authUsecase:     authUsecase,
		userUsecase:     userUsecase,
	})
}
