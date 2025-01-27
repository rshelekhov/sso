package v1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/domain"
)

var ErrRequestIDNotFoundInContext = errors.New("request ID not found in context")

func (ar *Router) getRequestID(ctx context.Context) (string, error) {
	requestID, ok := ar.requestIDMgr.FromContext(ctx)
	if !ok {
		return "", ErrRequestIDNotFoundInContext
	}

	return requestID, nil
}

func (ar *Router) getAndValidateAppID(ctx context.Context) (string, error) {
	appID, err := ar.getAppID(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToGetAppID, err)
	}

	if err = ar.validateAppID(ctx, appID); err != nil {
		return "", fmt.Errorf("%w: %w", controller.ErrFailedToValidateAppID, err)
	}

	return appID, nil
}

func (ar *Router) getAppID(ctx context.Context) (string, error) {
	appID, ok := ar.appIDMgr.FromContext(ctx)
	if !ok {
		return "", controller.ErrAppIDNotFoundInContext
	}

	return appID, nil
}

func (ar *Router) validateAppID(ctx context.Context, appID string) error {
	if err := ar.appValidator.ValidateAppID(ctx, appID); err != nil {
		if errors.Is(err, domain.ErrAppNotFound) {
			return controller.ErrAppNotFound
		}
		return err
	}
	return nil
}

type errorResponse struct {
	Error      error     `json:"error"`
	StatusCode int       `json:"status_code"`
	Location   string    `json:"location"`
	Time       time.Time `json:"time"`
}

func (ar *Router) handleResponseError(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	err error,
) {
	ar.responseError(w, r, status, err)
}

func (ar *Router) handleInternalServerError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	ar.responseError(w, r, http.StatusInternalServerError, err)
}

func (ar *Router) responseError(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	error error,
) {
	_, file, line, ok := getCaller()
	if !ok {
		file = "unknown file"
		line = -1
	}

	// op := runtime.FuncForPC(pc).Name()
	location := fmt.Sprintf("%s:%d", file, line)

	resp := &errorResponse{}

	resp.Error = error
	resp.StatusCode = status
	resp.Location = location
	resp.Time = time.Now()

	render.Status(r, status)
	render.JSON(w, r, resp)
}

func getCaller() (pc uintptr, file string, line int, ok bool) {
	pcs := make([]uintptr, 10)
	n := runtime.Callers(2, pcs)
	if n == 0 {
		return
	}

	frames := runtime.CallersFrames(pcs[:n])

	frame, more := frames.Next()
	if !more {
		return
	}

	for {
		frame, more = frames.Next()
		if strings.Contains(frame.Function, "sso") {
			return frame.PC, frame.File, frame.Line, true
		}
		if !more {
			break
		}
	}

	return 0, "unknown file", -1, false
}
