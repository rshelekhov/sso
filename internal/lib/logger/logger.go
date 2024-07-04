package logger

import (
	"context"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/logger/handler/slogpretty"
	"log/slog"
	"os"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

type HandlerMiddleware struct {
	next slog.Handler
}

func NewHandlerMiddleware(next slog.Handler) *HandlerMiddleware {
	return &HandlerMiddleware{
		next: next,
	}
}

func (h *HandlerMiddleware) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *HandlerMiddleware) Handle(ctx context.Context, r slog.Record) error {
	return h.next.Handle(ctx, r)
}

func (h *HandlerMiddleware) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &HandlerMiddleware{
		next: h.next.WithAttrs(attrs),
	}
}

func (h *HandlerMiddleware) WithGroup(name string) slog.Handler {
	return &HandlerMiddleware{
		next: h.next.WithGroup(name),
	}
}

func SetupLogger(env string) *slog.Logger {
	var handler slog.Handler

	switch env {
	case envLocal:
		handler = slogpretty.NewPrettyHandler(os.Stdout, &slogpretty.Options{
			Level:     slog.LevelDebug,
			AddSource: true,
		})
	case envDev:
		handler = slog.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}))
	case envProd:
		handler = slog.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		}))
	}

	handler = NewHandlerMiddleware(handler)
	log := slog.New(handler)

	return log
}

// TODO: use this method for errors!
func Err(err error) slog.Attr {
	return slog.Attr{
		Key:   key.Error,
		Value: slog.StringValue(err.Error()),
	}
}
