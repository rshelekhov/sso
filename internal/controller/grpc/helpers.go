package grpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/rshelekhov/sso/internal/lib/interceptor/requestid"
)

func (c *gRPCController) getRequestID(ctx context.Context) (string, error) {
	requestID, ok := requestid.FromContext(ctx)
	if !ok {
		return "", controller.ErrRequestIDNotFoundInContext
	}

	return requestID, nil
}

func (c *gRPCController) getAndValidateAppID(ctx context.Context) (string, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToGetAppID, err)
	}

	if err = c.validateAppID(ctx, appID); err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToValidateAppID, err)
	}

	return appID, nil
}

func (c *gRPCController) getAppID(ctx context.Context) (string, error) {
	appID, ok := appid.FromContext(ctx)
	if !ok {
		return "", controller.ErrAppIDNotFoundInContext
	}

	return appID, nil
}

func (c *gRPCController) validateAppID(ctx context.Context, appID string) error {
	if err := c.appValidator.ValidateAppID(ctx, appID); err != nil {
		if errors.Is(err, domain.ErrAppNotFound) {
			return controller.ErrAppNotFound
		}
		return err
	}
	return nil
}
