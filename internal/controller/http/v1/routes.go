package v1

import (
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/go-chi/render"
	mwlogger "github.com/rshelekhov/sso/internal/lib/middleware/logger"
)

func (ar *Router) initRoutes() *chi.Mux {
	r := chi.NewRouter()

	// Strip trailing slashes
	r.Use(middleware.StripSlashes)

	// Add request_id to each request, for tracing purposes
	r.Use(ar.requestIDMgr.HTTPMiddleware)

	// Add app_id to each request
	r.Use(ar.appIDMgr.HTTPMiddleware)

	// Logging of all requests
	r.Use(middleware.Logger)

	// By default, middleware.logger uses its own internal logger,
	// which should be overridden to use ours. Otherwise, problems
	// may arise - for example, with log collection. We can use
	// our own middleware to log requests:
	r.Use(mwlogger.New(ar.log, ar.requestIDMgr))

	// If a panic happens somewhere inside the httpserver (request handler),
	// the application should not crash.
	r.Use(middleware.Recoverer)

	// Set the content type to application/json
	r.Use(render.SetContentType(render.ContentTypeJSON))

	// Enable http rate request limiter of number of requests per minute per IP
	r.Use(httprate.LimitByIP(ar.cfg.RequestLimitByIP, 1*time.Minute))

	// Health check
	r.Get("/health", HealthRead())

	// JWKS endpoint
	r.Get("/.well-known/jwks.json", ar.GetJWKS())

	r.Group(func(r chi.Router) {
		// Parser of incoming request URLs
		r.Use(middleware.URLFormat)

		r.Route("/v1", func(r chi.Router) {
			// Public routes
			r.Group(func(r chi.Router) {
			})

			// Protected routes
			//r.Group(func(r chi.Router) {
			//	r.Use(ar.jwtMgr.HTTPMiddleware)
			//})
		})
	})

	return r
}
