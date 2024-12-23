package grpc

import (
	"context"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/pkg/middleware"
	"github.com/rshelekhov/sso/src/domain"
	"github.com/rshelekhov/sso/src/domain/service/appvalidator"
	"github.com/rshelekhov/sso/src/domain/usecase"
	"log/slog"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"google.golang.org/grpc"
)

type controller struct {
	ssov1.UnimplementedAuthServer
	log          *slog.Logger
	requestIDMgr middleware.ContextManager
	appIDMgr     middleware.ContextManager
	appValidator appvalidator.Validator
	appUsecase   usecase.AppProvider
	authUsecase  usecase.AuthProvider
	userUsecase  usecase.UserProvider
}

func RegisterController(
	gRPC *grpc.Server,
	log *slog.Logger,
	requestIDMgr middleware.ContextManager,
	appIDMgr middleware.ContextManager,
	appValidator appvalidator.Validator,
	appUsecase usecase.AppProvider,
	authUsecase usecase.AuthProvider,
	userUsecase usecase.UserProvider,
) {
	ssov1.RegisterAuthServer(gRPC, &controller{
		log:          log,
		requestIDMgr: requestIDMgr,
		appIDMgr:     appIDMgr,
		appValidator: appValidator,
		appUsecase:   appUsecase,
		authUsecase:  authUsecase,
		userUsecase:  userUsecase,
	})
}

var (
	ErrValidationError             = errors.New("validation error")
	ErrRequestIDNotFoundInContext  = errors.New("request ID not found in context")
	ErrAppIDNotFoundInContext      = errors.New("app ID not found in context")
	ErrFailedToGetRequestID        = errors.New("failed to get requestID")
	ErrFailedToGetAppID            = errors.New("failed to get appID")
	ErrFailedToValidateAppID       = errors.New("failed to validate appID")
	ErrFailedToGetAndValidateAppID = errors.New("failed to get and validate appID")
	ErrAppNotFound                 = errors.New("app not found")

	ErrFailedToLoginUser      = errors.New("failed to login user")
	ErrFailedToRegisterUser   = errors.New("failed to register user")
	ErrFailedToVerifyEmail    = errors.New("failed to verify email")
	ErrFailedToResetPassword  = errors.New("failed to reset password")
	ErrFailedToChangePassword = errors.New("failed to change password")
	ErrFailedToLogoutUser     = errors.New("failed to logout user")
	ErrFailedToRefreshTokens  = errors.New("failed to refresh tokens")
	ErrFailedToGetJWKS        = errors.New("failed to get JWKS")

	ErrFailedToGetUser    = errors.New("failed to get user")
	ErrFailedToUpdateUser = errors.New("failed to update user")
	ErrFailedToDeleteUser = errors.New("failed to delete user")
)

func (c *controller) getRequestID(ctx context.Context) (string, error) {
	requestID, ok := c.requestIDMgr.FromContext(ctx)
	if !ok {
		return "", ErrRequestIDNotFoundInContext
	}

	return requestID, nil
}

func (c *controller) getAndValidateAppID(ctx context.Context) (string, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrFailedToGetAppID, err)
	}

	if err = c.validateAppID(ctx, appID); err != nil {
		return "", fmt.Errorf("%w: %w", ErrFailedToValidateAppID, err)
	}

	return appID, nil
}

func (c *controller) getAppID(ctx context.Context) (string, error) {
	appID, ok := c.appIDMgr.FromContext(ctx)
	if !ok {
		return "", ErrAppIDNotFoundInContext
	}

	return appID, nil
}

func (c *controller) validateAppID(ctx context.Context, appID string) error {
	if err := c.appValidator.ValidateAppID(ctx, appID); err != nil {
		if errors.Is(err, domain.ErrAppNotFound) {
			return ErrAppNotFound
		}
		return err
	}
	return nil
}
