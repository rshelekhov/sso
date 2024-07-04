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
		LogoutUser(ctx context.Context, data model.UserDeviceRequestData, appID string) error
		RefreshTokens(ctx context.Context, data *model.RefreshRequestData) (model.TokenData, error)
		GetJWKS(ctx context.Context, data *model.JWKSRequestData) (model.JWKS, error)
		GetUserByID(ctx context.Context, data *model.UserRequestData) (model.User, error)
		UpdateUser(ctx context.Context, data *model.UserRequestData) error
		DeleteUser(ctx context.Context, data *model.UserRequestData) error
	}

	AuthStorage interface {
		Transaction(ctx context.Context, fn func(storage AuthStorage) error) error
		ValidateAppID(ctx context.Context, appID string) error
		CreateUser(ctx context.Context, user model.User) error
		GetUserByEmail(ctx context.Context, email, appID string) (model.User, error)
		GetUserByID(ctx context.Context, userID, appID string) (model.User, error)
		GetUserData(ctx context.Context, userID, appID string) (model.User, error)
		GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
		UpdateLatestVisitedAt(ctx context.Context, deviceID, appID string, latestLoginAt time.Time) error
		RegisterDevice(ctx context.Context, device model.UserDevice) error
		CreateUserSession(ctx context.Context, session model.Session) error
		GetSessionByRefreshToken(ctx context.Context, refreshToken string) (model.Session, error)
		DeleteRefreshToken(ctx context.Context, refreshToken string) error
		DeleteSession(ctx context.Context, userID, deviceID, appID string) error
		CheckEmailUniqueness(ctx context.Context, user model.User) error
		UpdateUser(ctx context.Context, user model.User) error
		DeleteUser(ctx context.Context, user model.User) error
	}
)
