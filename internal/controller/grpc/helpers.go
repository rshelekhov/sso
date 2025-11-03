package grpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/rshelekhov/golib/middleware/requestid"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/e"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
)

func (c *gRPCController) setupRequest(ctx context.Context, method string) (context.Context, *slog.Logger, error) {
	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return ctx, nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))
	return ctx, log, nil
}

func (c *gRPCController) validateRequest(ctx context.Context, log *slog.Logger, req any, validateFn func(any) error) error {
	if err := validateFn(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}
	return nil
}

func (c *gRPCController) getRequestID(ctx context.Context) (string, error) {
	requestID, ok := requestid.FromContext(ctx)
	if !ok {
		return "", controller.ErrRequestIDNotFoundInContext
	}

	return requestID, nil
}

func (c *gRPCController) getAndValidateClientID(ctx context.Context, log *slog.Logger) (string, error) {
	clientID, err := c.getClientID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetClientID, err)
		return "", mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetClientID, err))
	}

	if err = c.validateClientID(ctx, clientID); err != nil {
		e.LogError(ctx, log, controller.ErrFailedToValidateClientID, err)
		return "", mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToValidateClientID, err))
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
