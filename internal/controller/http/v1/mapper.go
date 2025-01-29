package v1

import (
	"errors"
	"net/http"

	"github.com/rshelekhov/sso/internal/domain"
)

var errorToStatus = map[error]int{
	domain.ErrUserNotFound: http.StatusNotFound,
}

func (ar *Router) mapErrorToHTTPStatus(w http.ResponseWriter, r *http.Request, err error) {
	for domainErr, statusCode := range errorToStatus {
		if errors.Is(err, domainErr) {
			ar.handleResponseError(w, r, statusCode, err)
		}
	}

	if err != nil {
		ar.handleInternalServerError(w, r, err)
	}
}
