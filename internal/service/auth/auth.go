package auth

import (
	"context"
	"github.com/rshelekhov/sso/internal/logger"
	"github.com/rshelekhov/sso/internal/model"
)

type Auth struct {
	log logger.Interface
}

type UserCreater interface {
	CreateUser(ctx context.Context, email string, passwordHash []byte) (userID string, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (model.User, error)
}
