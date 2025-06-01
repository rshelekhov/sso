package rbac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/service/rbac"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
)

type Interceptor struct {
	log           *slog.Logger
	cfg           *config.GRPCMethodsConfig
	appValidator  appvalidator.Validator
	roleExtractor RoleExtractor
}

type RoleExtractor interface {
	ExtractUserRoleFromTokenInContext(ctx context.Context, appID string) (string, error)
}

func NewInterceptor(
	logger *slog.Logger,
	cfg *config.GRPCMethodsConfig,
	appValidator appvalidator.Validator,
	roleExtractor RoleExtractor,
) *Interceptor {
	return &Interceptor{
		log:           logger,
		cfg:           cfg,
		appValidator:  appValidator,
		roleExtractor: roleExtractor,
	}
}

func (i *Interceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		methodConfigs := i.cfg.GetMethodConfigs()
		methodConfig, exists := methodConfigs[info.FullMethod]
		if !exists {
			i.log.Error("method not found in config", slog.String("method", info.FullMethod))
			return nil, status.Error(codes.PermissionDenied, "method not configured")
		}

		// Skip RBAC check for methods that don't require AppID
		if !methodConfig.RequireAppID {
			return handler(ctx, req)
		}

		appID, err := i.getAndValidateAppID(ctx)
		if err != nil {
			i.log.Error("failed to get and validate appID", slog.String("error", err.Error()))
			return nil, status.Error(codes.Unauthenticated, "failed to get and validate appID")
		}

		log := i.log.With(slog.String("appID", appID))

		// Skip role check for methods that don't require JWT
		if !methodConfig.RequireJWT {
			return handler(ctx, req)
		}

		userRole, err := i.roleExtractor.ExtractUserRoleFromTokenInContext(ctx, appID)
		if err != nil {
			log.Error("failed to extract user role from context", slog.String("error", err.Error()))
			return nil, status.Error(codes.Unauthenticated, "failed to extract user role from context")
		}

		role := rbac.Role(userRole)
		if !rbac.IsValidRole(role) {
			log.Error("invalid role", slog.String("role", userRole))
			return nil, status.Error(codes.PermissionDenied, "invalid role")
		}

		if !rbac.HasPermission(role, methodConfig.Permission) {
			log.Warn("permission denied",
				slog.String("method", info.FullMethod),
				slog.String("role", string(role)),
				slog.String("required_permission", string(methodConfig.Permission)),
			)
			return nil, status.Error(codes.PermissionDenied, fmt.Sprintf("insufficient permissions for %s", info.FullMethod))
		}

		return handler(ctx, req)
	}
}

func (i *Interceptor) getAndValidateAppID(ctx context.Context) (string, error) {
	appID, err := i.getAppID(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToGetAppID, err)
	}

	if err = i.validateAppID(ctx, appID); err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToValidateAppID, err)
	}

	return appID, nil
}

func (i *Interceptor) getAppID(ctx context.Context) (string, error) {
	appID, ok := appid.FromContext(ctx)
	if !ok {
		return "", controller.ErrAppIDNotFoundInContext
	}

	return appID, nil
}

func (i *Interceptor) validateAppID(ctx context.Context, appID string) error {
	if err := i.appValidator.ValidateAppID(ctx, appID); err != nil {
		if errors.Is(err, domain.ErrAppNotFound) {
			return controller.ErrAppNotFound
		}
		return err
	}
	return nil
}
