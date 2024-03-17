package slogdiscard

import (
	"context"
	"github.com/rshelekhov/sso/internal/logger"
	"log/slog"
)

// In this form, the logger will ignore all messages we send to it -
// we will need this in tests.

func NewDiscardLogger() *logger.Logger {
	return &logger.Logger{Logger: slog.New(NewDiscardHandler())}
}

type DiscardHandler struct{}

func (d DiscardHandler) Enabled(_ context.Context, _ slog.Level) bool {
	// Always returns false, since the log entry is ignored
	return false
}

func (d DiscardHandler) Handle(_ context.Context, _ slog.Record) error {
	return nil
}

func (d DiscardHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	// Returns the same controller, since there is no group to be saved
	return d
}

func (d DiscardHandler) WithGroup(_ string) slog.Handler {
	// Returns the same controller, since there is no group to be saved
	return d
}

// NewDiscardHandler ...
func NewDiscardHandler() *DiscardHandler {
	return &DiscardHandler{}
}
