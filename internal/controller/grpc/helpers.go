package grpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/rshelekhov/sso/internal/lib/interceptor/requestid"
)

func (c *gRPCController) getRequestID(ctx context.Context) (string, error) {
	requestID, ok := requestid.FromContext(ctx)
	if !ok {
		return "", controller.ErrRequestIDNotFoundInContext
	}

	return requestID, nil
}

func (c *gRPCController) getAndValidateClientID(ctx context.Context) (string, error) {
	clientID, err := c.getClientID(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToGetClientID, err)
	}

	if err = c.validateClientID(ctx, clientID); err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToValidateClientID, err)
	}

	return clientID, nil
}

func (c *gRPCController) getClientID(ctx context.Context) (string, error) {
	clientID, ok := clientid.FromContext(ctx)
	if !ok {
		return "", controller.ErrClientIDNotFoundInContext
	}

	return clientID, nil
}

func (c *gRPCController) validateClientID(ctx context.Context, clientID string) error {
	if err := c.clientValidator.ValidateClientID(ctx, clientID); err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			return controller.ErrClientNotFound
		}
		return err
	}
	return nil
}
