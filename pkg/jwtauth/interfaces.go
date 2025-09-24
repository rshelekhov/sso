package jwtauth

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
)

type (
	Extractor interface {
		ExtractTokenFromGRPC(ctx context.Context) (string, error)
		ExtractTokenFromHTTP(r *http.Request) (string, error)
		ExtractTokenFromCookies(r *http.Request) (string, error)
		ExtractRefreshTokenFromCookies(r *http.Request) (string, error)
	}

	ContextManager interface {
		FromContext(ctx context.Context) (string, bool)
		ToContext(ctx context.Context, value string) context.Context
	}

	TokenParser interface {
		ParseToken(clientID, token string) (*jwt.Token, error)
		ExtractUserID(ctx context.Context, clientID string) (string, error)
	}

	TokenSender interface {
		SendTokensToWeb(w http.ResponseWriter, resp *TokenResponse, httpStatus int)
		SendTokensToMobileApp(w http.ResponseWriter, resp *TokenResponse, httpStatus int)
	}

	Middleware interface {
		UnaryServerInterceptor() grpc.UnaryServerInterceptor
		HTTPMiddleware(next http.Handler) http.Handler
	}

	MetricsRecorder interface {
		// Token validation
		RecordTokenValidationSuccess(ctx context.Context, clientID string)
		RecordTokenValidationExpired(ctx context.Context, clientID string)
		RecordTokenValidationInvalid(ctx context.Context, clientID string)
		RecordTokenValidationMalformed(ctx context.Context, clientID string)
		RecordTokenValidationDuration(ctx context.Context, clientID string, duration float64)

		// JWKS operations
		RecordJWKSCacheHit(ctx context.Context, clientID string)
		RecordJWKSCacheMiss(ctx context.Context, clientID string)
	}

	Manager interface {
		Extractor
		ContextManager
		TokenParser
		TokenSender
		Middleware
	}
)
