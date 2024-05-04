package logger

import (
	"context"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/logger/handlers/slogpretty"
	"log/slog"
	"os"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

type Logger struct {
	*slog.Logger
}

func SetupLogger(env string) *Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = setupPrettySlog()
	case envDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}))
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		}))
	}

	return &Logger{Logger: log}
}

func setupPrettySlog() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}

	handler := opts.NewPrettyHandler(os.Stdout)

	return slog.New(handler)
}

func Err(err error) slog.Attr {
	return slog.Attr{
		Key:   key.Error,
		Value: slog.StringValue(err.Error()),
	}
}

func LogWithRequest(log *slog.Logger, reqID string) *slog.Logger {
	log.With(
		slog.String("request_id", reqID),
	)

	return log
}

func (l *Logger) With(args ...any) *Logger {
	l.Logger.With(args...)
	return l
}

func (l *Logger) Debug(msg string, attrs ...interface{}) {
	l.Logger.Debug(msg, attrs...)
}

func (l *Logger) Info(msg string, attrs ...interface{}) {
	l.Logger.Info(msg, attrs...)
}

func (l *Logger) Warn(msg string, attrs ...interface{}) {
	l.Logger.Warn(msg, attrs...)
}

func (l *Logger) Error(msg string, attrs ...interface{}) {
	l.Logger.Error(msg, attrs...)
}
