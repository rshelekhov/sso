package port

import (
	"context"
	"github.com/rshelekhov/sso/internal/model"
)

type (
	AppUsecase interface {
		RegisterApp(ctx context.Context, appName string) error
	}

	AppStorage interface {
		RegisterApp(ctx context.Context, data model.AppData) error
	}
)
