package logger

import (
	"log/slog"
	"net/http"
	"time"

	chiMiddleware "github.com/go-chi/chi/middleware"
	"github.com/rshelekhov/sso/pkg/middleware"
)

func New(log *slog.Logger, reqIDManager middleware.ContextManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		log = log.With(slog.String("component", "middleware/logger"))

		log.Info("logger middleware enabled")

		fn := func(w http.ResponseWriter, r *http.Request) {
			reqID, ok := reqIDManager.FromContext(r.Context())
			if !ok {
				reqID = "unknown requestID"
			}

			// Collect initial information about the request
			entry := log.With(
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.String("request_id", reqID),
			)

			// Create a wrapper around `http.ResponseWriter`
			// to get the response details
			ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// Moment of receiving the request to calculate
			t1 := time.Now()

			// The record will be sent to the log after the request
			// has been processed
			defer func() {
				entry.Info("request completed",
					slog.Int("status", ww.Status()),
					slog.Int("bytes", ww.BytesWritten()),
					slog.String("duration", time.Since(t1).String()),
				)
			}()

			// Pass control to the next handler in the middleware chain
			next.ServeHTTP(ww, r)
		}

		// Return the handler created above by casting it
		// to the type http.HandlerFunc
		return http.HandlerFunc(fn)
	}
}
