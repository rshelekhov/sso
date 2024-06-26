package port

import (
	"context"
	"github.com/rshelekhov/sso/internal/model"
	"log/slog"
	"time"
)

type (
	AuthUsecase interface {
		Login(ctx context.Context, data *model.UserRequestData) (model.TokenData, error)
		RegisterNewUser(ctx context.Context, data *model.UserRequestData) (model.TokenData, error)
		CreateUserSession(ctx context.Context, log *slog.Logger, user model.User, data model.UserDeviceRequestData) (model.TokenData, error)
		LogoutUser(ctx context.Context, data model.UserDeviceRequestData, appID int32) error
		RefreshTokens(ctx context.Context, data *model.RefreshRequestData) (model.TokenData, error)
		GetJWKS(ctx context.Context, data *model.JWKSRequestData) (model.JWKS, error)
		GetUserByID(ctx context.Context, data *model.UserRequestData) (model.User, error)
		UpdateUser(ctx context.Context, data *model.UserRequestData) error
		DeleteUser(ctx context.Context, data *model.UserRequestData) error
	}

	AuthStorage interface {
		Transaction(ctx context.Context, fn func(storage AuthStorage) error) error
		ValidateAppID(ctx context.Context, appID int32) error
		CreateUser(ctx context.Context, user model.User) error
		GetUserByEmail(ctx context.Context, email string, appID int32) (model.User, error)
		GetUserByID(ctx context.Context, userID string, appID int32) (model.User, error)
		GetUserData(ctx context.Context, userID string, appID int32) (model.User, error)
		GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
		UpdateLastLoginAt(ctx context.Context, deviceID string, appID int32, latestLoginAt time.Time) error
		RegisterDevice(ctx context.Context, device model.UserDevice) error
		CreateUserSession(ctx context.Context, session model.Session) error
		GetSessionByRefreshToken(ctx context.Context, refreshToken string) (model.Session, error)
		DeleteRefreshToken(ctx context.Context, refreshToken string) error
		DeleteSession(ctx context.Context, userID, deviceID string, appID int32) error
		CheckEmailUniqueness(ctx context.Context, user model.User) error
		UpdateUser(ctx context.Context, user model.User) error
		DeleteUser(ctx context.Context, user model.User) error
	}
)
