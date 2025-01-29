package middleware

import (
	"context"
	"net/http"

	"google.golang.org/grpc"
)

type (
	Extractor interface {
		ExtractFromGRPC(ctx context.Context) (string, error)
		ExtractFromHTTP(r *http.Request) (string, error)
	}

	ContextManager interface {
		FromContext(ctx context.Context) (string, bool)
		ToContext(ctx context.Context, value string) context.Context
	}

	Middleware interface {
		UnaryServerInterceptor() grpc.UnaryServerInterceptor
		HTTPMiddleware(next http.Handler) http.Handler
	}

	Manager interface {
		Extractor
		ContextManager
		Middleware
	}
)
