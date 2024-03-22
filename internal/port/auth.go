package port

import (
	"context"
	"github.com/rshelekhov/jwtauth"
	"github.com/rshelekhov/sso/internal/model"
	"log/slog"
	"time"
)

type (
	AuthUsecase interface {
		Login(ctx context.Context, data *model.UserRequestData, userDevice model.UserDeviceRequestData) (tokenData jwtauth.TokenData, err error)
		RegisterNewUser(ctx context.Context, data *model.UserRequestData, userDevice model.UserDeviceRequestData) (tokenData jwtauth.TokenData, err error)
		CreateUserSession(ctx context.Context, log *slog.Logger, userID string, data model.UserDeviceRequestData) (tokenData jwtauth.TokenData, err error)
		// ExtractUserDeviceData(ctx context.Context, userEmail string) (model.UserDeviceRequestData, error)
	}

	AuthStorage interface {
		CreateUser(ctx context.Context, data model.User) error
		GetUserByEmail(ctx context.Context, email string) (model.User, error)
		GetUserData(ctx context.Context, userID string) (model.User, error)

		GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
		UpdateLastVisitedAt(ctx context.Context, deviceID string, latestLoginAt time.Time) error
		RegisterDevice(ctx context.Context, device model.UserDevice) error
		CreateUserSession(ctx context.Context, session model.Session) error
	}
)
