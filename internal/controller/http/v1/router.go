package v1

import (
	"log/slog"

	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/usecase/app"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	"github.com/rshelekhov/sso/pkg/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/rshelekhov/sso/internal/config/settings"
)

type Router struct {
	cfg          Config
	log          *slog.Logger
	requestIDMgr middleware.Manager
	appIDMgr     middleware.Manager
	jwtMgr       jwtauth.Manager
	appValidator appvalidator.Validator
	appUsecase   app.Usecase
	authUsecase  auth.Usecase
	userUsecase  user.Usecase
}

func NewRouter(
	cfg settings.HTTPServer,
	log *slog.Logger,
	requestIDMgr middleware.Manager,
	appIDMgr middleware.Manager,
	jwtMgr jwtauth.Manager,
	appValidator appvalidator.Validator,
	appUsecase app.Usecase,
	authUsecase auth.Usecase,
	userUsecase user.Usecase,
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
		appUsecase:   appUsecase,
		authUsecase:  authUsecase,
		userUsecase:  userUsecase,
	}

	return ar.initRoutes()
}

type Config struct {
	RequestLimitByIP int
}
