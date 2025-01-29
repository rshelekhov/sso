package v1

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/render"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/lib/e"
)

func (ar *Router) GetJWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const method = "controller.http.GetJWKS"

		ar.log.Info("started GetJWKS method")

		ctx := r.Context()
		log := ar.log.With(slog.String("method", method))

		reqID, err := ar.getRequestID(ctx)
		if err != nil {
			e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
			ar.mapErrorToHTTPStatus(w, r, fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
			return
		}

		log = log.With(slog.String("requestID", reqID))

		appID, err := ar.getAndValidateAppID(ctx)
		if err != nil {
			e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
			ar.mapErrorToHTTPStatus(w, r, fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
			return
		}

		jwks, err := ar.authUsecase.GetJWKS(ctx, appID)
		if err != nil {
			e.LogError(ctx, log, controller.ErrFailedToGetJWKS, err)
			ar.mapErrorToHTTPStatus(w, r, fmt.Errorf("%w: %w", controller.ErrFailedToGetJWKS, err))
			return
		}

		render.Status(r, http.StatusOK)
		render.JSON(w, r, jwks)
	}
}
