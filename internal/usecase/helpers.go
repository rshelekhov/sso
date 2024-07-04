package usecase

import (
	"context"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"log/slog"
)

func logFailedToGetRequestID(ctx context.Context, log *slog.Logger, err error, method string) {
	log.LogAttrs(ctx, slog.LevelError, le.ErrFailedToGetRequestIDFromCtx.Error(),
		slog.String(key.Error, err.Error()),
		slog.String(key.Method, method),
	)
}

func logFailedToGetUserID(ctx context.Context, log *slog.Logger, err error) {
	log.LogAttrs(ctx, slog.LevelError, le.ErrFailedToGetUserIDFromToken.Error(),
		slog.String(key.Error, err.Error()),
	)
}

func logFailedToCreateUserSession(ctx context.Context, log *slog.Logger, err error, userID string) {
	log.LogAttrs(ctx, slog.LevelError, le.ErrFailedToCreateUserSession.Error(),
		slog.String(key.Error, err.Error()),
		slog.String(key.UserID, userID),
	)
}

func logFailedToCommitTransaction(ctx context.Context, log *slog.Logger, err error, userID string) {
	log.LogAttrs(ctx, slog.LevelError, le.ErrFailedToCommitTransaction.Error(),
		slog.String(key.Error, err.Error()),
		slog.String(key.UserID, userID),
	)
}

// TODO: add logError function which will be used in all usecases
// this function should have an ability to get many arguments
