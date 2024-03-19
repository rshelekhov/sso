package service

import (
	"context"
	jwt "github.com/rshelekhov/sso-jwt"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/port"
	"log/slog"
)

type Auth struct {
	log     logger.Interface
	storage port.AuthStorage
	jwt     *jwt.TokenService
}

// New returns a new instance of the Auth service
func New(
	log logger.Interface,
	storage port.AuthStorage,
	jwt *jwt.TokenService,
) *Auth {
	return &Auth{
		log:     log,
		storage: storage,
		jwt:     jwt,
	}
}

// Login checks if user with given credentials exists in the system
//
// Is user exists, but password is incorrect, it will return an error
// If user doesn't exist, it will return an error
func (a *Auth) Login(ctx context.Context, email, password string, appID int) (token string, err error) {
	return "", nil
}

// RegisterNewUser creates new user in the system and returns token
//
// If user with given email already exists, it will return an error
func (a *Auth) CreateUser(ctx context.Context, email, password string) (userID string, err error) {
	const op = "service.Auth.CreateUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	exists, err := a.storage.UserExists(ctx, email)
	if err != nil {
		log.Error("failed to check if user exists", err)
		return "", err
	}

	if exists {
		return "", nil
	}

	return "", nil
}
