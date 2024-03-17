package port

import (
	"context"
	"github.com/rshelekhov/sso/internal/model"
)

type App interface {
	GetApp(ctx context.Context, appID int) (model.App, error)
}
