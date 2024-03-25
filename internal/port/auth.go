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
		Login(ctx context.Context, data *model.UserRequestData) (jwtauth.TokenData, error)
		RegisterNewUser(ctx context.Context, data *model.UserRequestData) (jwtauth.TokenData, error)
		CreateUserSession(ctx context.Context, log *slog.Logger, userID string, data model.UserDeviceRequestData) (jwtauth.TokenData, error)
		RefreshTokens(ctx context.Context, data *model.RefreshRequestData) (jwtauth.TokenData, error)
		LogoutUser(ctx context.Context, data model.UserDeviceRequestData) error
		GetUserByID(ctx context.Context, data *model.UserRequestData) (model.User, error)
		UpdateUser(ctx context.Context, data *model.UserRequestData) error
		DeleteUser(ctx context.Context, data *model.UserRequestData) error
	}

	AuthStorage interface {
		CreateUser(ctx context.Context, user model.User) error
		GetUserByEmail(ctx context.Context, email string, appID int32) (model.User, error)
		GetUserByID(ctx context.Context, userID string, appID int32) (model.User, error)
		GetUserData(ctx context.Context, userID string, appID int32) (model.User, error)
		GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
		UpdateLastVisitedAt(ctx context.Context, deviceID string, appID int32, latestLoginAt time.Time) error
		RegisterDevice(ctx context.Context, device model.UserDevice) error
		CreateUserSession(ctx context.Context, session model.Session) error
		GetSessionByRefreshToken(ctx context.Context, refreshToken string) (model.Session, error)
		DeleteRefreshToken(ctx context.Context, refreshToken string) error
		DeleteSession(ctx context.Context, userID, deviceID string) error
		CheckEmailUniqueness(ctx context.Context, user model.User) error
		UpdateUser(ctx context.Context, user model.User) error
		DeleteUser(ctx context.Context, user model.User) error
	}
)
