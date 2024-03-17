package logger

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/middleware"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

type Interface interface {
	With(args ...any) *Logger
	Debug(msg string, attrs ...interface{})
	Info(msg string, attrs ...interface{})
	Warn(msg string, attrs ...interface{})
	Error(msg string, attrs ...interface{})
}

type Logger struct {
	Logger *slog.Logger
}

func SetupLogger(env string) *Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	return &Logger{Logger: log}
}

// Err ...
func Err(err error) slog.Attr {
	return slog.Attr{
		Key:   "error",
		Value: slog.StringValue(err.Error()),
	}
}

func LogWithRequest(log Interface, op string, r *http.Request) Interface {
	log.With(
		slog.String("op", op),
		slog.String("request_id", middleware.GetReqID(r.Context())),
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
