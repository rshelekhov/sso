package port

import (
	"context"
	"github.com/rshelekhov/sso/internal/model"
)

type (
	AuthService interface {
		Login(ctx context.Context, email, password string, appID int) (token string, err error)
		RegisterNewUser(ctx context.Context, email, password string) (token string, err error)
	}

	AuthStorage interface {
		CreateUser(ctx context.Context, email string, passwordHash []byte) (userID string, err error)
		GetUser(ctx context.Context, email string) (model.User, error)
	}
)
