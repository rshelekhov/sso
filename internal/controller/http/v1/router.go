package v1

import (
	"context"
	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/pkg/middleware"
)

type Router struct {
	cfg          Config
	log          *slog.Logger
	requestIDMgr middleware.Manager
	appIDMgr     middleware.Manager
	jwtMgr       jwtauth.Manager
	appValidator appvalidator.Validator
	authUsecase  AuthUsecase
}

type AuthUsecase interface {
	GetJWKS(ctx context.Context, appID string) (entity.JWKS, error)
}

func NewRouter(
	cfg settings.HTTPServer,
	log *slog.Logger,
	requestIDMgr middleware.Manager,
	appIDMgr middleware.Manager,
	jwtMgr jwtauth.Manager,
	appValidator appvalidator.Validator,
	authUsecase AuthUsecase,
) *chi.Mux {
	config := Config{
		RequestLimitByIP: cfg.RequestLimitByIP,
	}

	ar := &Router{
		cfg:          config,
		log:          log,
		requestIDMgr: requestIDMgr,
		appIDMgr:     appIDMgr,
		jwtMgr:       jwtMgr,
		appValidator: appValidator,
		authUsecase:  authUsecase,
	}

	return ar.initRoutes()
}

type Config struct {
	RequestLimitByIP int
}
