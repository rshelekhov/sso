package session

import (
	"context"
	"errors"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/session/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCreateUserSession(t *testing.T) {
	mockJWTManager := new(mocks.JWTManager)
	mockSessionStorage := new(mocks.Storage)

	sessionService := NewService(mockJWTManager, mockSessionStorage)

	ctx := context.Background()
	sessionReqData := entity.SessionRequestData{
		UserID: "test-user-id",
		AppID:  "test-app-id",
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: "test-user-agent",
			IP:        "test-ip",
		},
	}

	t.Run("Success", func(t *testing.T) {
		mockJWTManager.
			On("Issuer").
			Once().
			Return("test-issuer")

		mockJWTManager.
			On("AccessTokenTTL").
			Once().
			Return(15 * time.Minute)

		mockJWTManager.
			On("RefreshTokenTTL").
			Once().
			Return(7 * 24 * time.Hour)

		mockJWTManager.
			On("Kid", sessionReqData.AppID).
			Once().
			Return("test-kid", nil)

		mockJWTManager.
			On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).
			Once().
			Return("test-access-token", nil)

		mockJWTManager.
			On("NewRefreshToken").
			Once().
			Return("test-refresh-token")

		mockJWTManager.
			On("RefreshTokenCookieDomain").
			Once().
			Return("test-cookie-domain")

		mockJWTManager.
			On("RefreshTokenCookiePath").
			Once().
			Return("test-cookie-path")

		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("test-device-id", nil)

		mockSessionStorage.
			On("CreateSession", ctx, mock.Anything).
			Once().
			Return(nil)

		mockSessionStorage.
			On("UpdateLastVisitedAt", ctx, mock.Anything).
			Once().
			Return(nil)

		sessionReqData.DeviceID = "test-device-id"
		expectedTokens := entity.SessionTokens{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			Domain:       "test-cookie-domain",
			Path:         "test-cookie-path",
			ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
			HTTPOnly:     true,
		}

		tokens, err := sessionService.CreateSession(ctx, sessionReqData)
		require.NoError(t, err)
		require.Equal(t, expectedTokens.AccessToken, tokens.AccessToken)
		require.Equal(t, expectedTokens.RefreshToken, tokens.RefreshToken)
		require.Equal(t, expectedTokens.Domain, tokens.Domain)
		require.Equal(t, expectedTokens.Path, tokens.Path)
		require.WithinDuration(t, expectedTokens.ExpiresAt, tokens.ExpiresAt, time.Second)
		require.Equal(t, expectedTokens.HTTPOnly, tokens.HTTPOnly)
	})

	t.Run("Error in getOrRegisterDeviceID", func(t *testing.T) {
		mockJWTManager.
			On("Issuer").
			Once().
			Return("test-issuer")

		mockJWTManager.
			On("AccessTokenTTL").
			Once().
			Return(15 * time.Minute)

		mockJWTManager.
			On("RefreshTokenTTL").
			Once().
			Return(7 * 24 * time.Hour)

		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("", errors.New("device not found"))

		tokens, err := sessionService.CreateSession(ctx, sessionReqData)
		require.Empty(t, tokens)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToGetDeviceID.Error())
	})

	t.Run("Error in getOrRegisterDeviceID – failed to register device", func(t *testing.T) {
		device := entity.NewUserDevice(sessionReqData)

		mockJWTManager.
			On("Issuer").
			Once().
			Return("test-issuer")

		mockJWTManager.
			On("AccessTokenTTL").
			Once().
			Return(15 * time.Minute)

		mockJWTManager.
			On("RefreshTokenTTL").
			Once().
			Return(7 * 24 * time.Hour)

		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("", storage.ErrUserDeviceNotFound)

		mockSessionStorage.
			On("RegisterDevice", ctx, mock.MatchedBy(func(d entity.UserDevice) bool {
				return d.UserID == device.UserID &&
					d.AppID == device.AppID &&
					d.UserAgent == device.UserAgent &&
					d.IP == device.IP &&
					d.Detached == device.Detached
			})).
			Once().
			Return(errors.New("failed to register device"))

		tokens, err := sessionService.CreateSession(ctx, sessionReqData)
		require.Empty(t, tokens)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToRegisterDevice.Error())
	})

	t.Run("Error in createTokens – failed to get keyID", func(t *testing.T) {
		mockJWTManager.
			On("Issuer").
			Once().
			Return("test-issuer")

		mockJWTManager.
			On("AccessTokenTTL").
			Once().
			Return(15 * time.Minute)

		mockJWTManager.
			On("RefreshTokenTTL").
			Once().
			Return(7 * 24 * time.Hour)

		mockJWTManager.
			On("Kid", sessionReqData.AppID).
			Once().
			Return("", domain.ErrFailedToGetKeyID)

		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("test-device-id", nil)

		tokens, err := sessionService.CreateSession(ctx, sessionReqData)
		require.Empty(t, tokens)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToGetKeyID.Error())
	})

	t.Run("Error in createTokens – failed to create access token", func(t *testing.T) {
		mockJWTManager.
			On("Issuer").
			Once().
			Return("test-issuer")

		mockJWTManager.
			On("AccessTokenTTL").
			Once().
			Return(15 * time.Minute)

		mockJWTManager.
			On("RefreshTokenTTL").
			Once().
			Return(7 * 24 * time.Hour)

		mockJWTManager.
			On("Kid", sessionReqData.AppID).
			Once().
			Return("test-kid", nil)

		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("test-device-id", nil)

		mockJWTManager.
			On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).
			Once().
			Return("", errors.New("failed to create access token"))

		tokens, err := sessionService.CreateSession(ctx, sessionReqData)
		require.Empty(t, tokens)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToCreateAccessToken.Error())
	})

	t.Run("Error in saveSession – failed to create user session", func(t *testing.T) {
		mockJWTManager.
			On("Issuer").
			Once().
			Return("test-issuer")

		mockJWTManager.
			On("AccessTokenTTL").
			Once().
			Return(15 * time.Minute)

		mockJWTManager.
			On("RefreshTokenTTL").
			Once().
			Return(7 * 24 * time.Hour)

		mockJWTManager.
			On("Kid", sessionReqData.AppID).
			Once().
			Return("test-kid", nil)

		mockJWTManager.
			On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).
			Once().
			Return("test-access-token", nil)

		mockJWTManager.
			On("NewRefreshToken").
			Once().
			Return("test-refresh-token")

		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("test-device-id", nil)

		mockSessionStorage.
			On("CreateSession", ctx, mock.Anything).
			Once().
			Return(errors.New("failed to create session"))

		tokens, err := sessionService.CreateSession(ctx, sessionReqData)
		require.Empty(t, tokens)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToCreateUserSession.Error())
	})

	t.Run("Error in saveSession – failed to update last visited at", func(t *testing.T) {
		mockJWTManager.
			On("Issuer").
			Once().
			Return("test-issuer")

		mockJWTManager.
			On("AccessTokenTTL").
			Once().
			Return(15 * time.Minute)

		mockJWTManager.
			On("RefreshTokenTTL").
			Once().
			Return(7 * 24 * time.Hour)

		mockJWTManager.
			On("Kid", sessionReqData.AppID).
			Once().
			Return("test-kid", nil)

		mockJWTManager.
			On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).
			Once().
			Return("test-access-token", nil)

		mockJWTManager.
			On("NewRefreshToken").
			Once().
			Return("test-refresh-token")

		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("test-device-id", nil)

		mockSessionStorage.
			On("CreateSession", ctx, mock.Anything).
			Once().
			Return(nil)

		mockSessionStorage.
			On("UpdateLastVisitedAt", ctx, mock.Anything).
			Once().
			Return(errors.New("failed to update last visited at"))

		tokens, err := sessionService.CreateSession(ctx, sessionReqData)
		require.Empty(t, tokens)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToUpdateLastVisitedAt.Error())
	})
}

func TestGetSessionByRefreshToken(t *testing.T) {
	mockSessionStorage := new(mocks.Storage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()
	refreshToken := "test-refresh-token"
	sessionReqData := entity.SessionRequestData{
		UserID: "test-user-id",
		AppID:  "test-app-id",
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: "test-user-agent",
			IP:        "test-ip",
		},
	}

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.
			On("GetSessionByRefreshToken", ctx, refreshToken).
			Once().
			Return(entity.Session{
				UserID:        sessionReqData.UserID,
				AppID:         sessionReqData.AppID,
				DeviceID:      "test-device-id",
				RefreshToken:  refreshToken,
				LastVisitedAt: time.Now(),
				ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
			}, nil)

		session, err := sessionService.GetSessionByRefreshToken(ctx, refreshToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)
	})

	t.Run("Error in GetSessionByRefreshToken", func(t *testing.T) {
		mockSessionStorage.
			On("GetSessionByRefreshToken", ctx, refreshToken).
			Once().
			Return(entity.Session{}, errors.New("failed to get session"))

		session, err := sessionService.GetSessionByRefreshToken(ctx, refreshToken)
		require.Empty(t, session)
		require.Error(t, err)
	})

	t.Run("Error in GetSessionByRefreshToken – session not found", func(t *testing.T) {
		mockSessionStorage.
			On("GetSessionByRefreshToken", ctx, refreshToken).
			Once().
			Return(entity.Session{}, storage.ErrSessionNotFound)

		session, err := sessionService.GetSessionByRefreshToken(ctx, refreshToken)
		require.Empty(t, session)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrSessionNotFound.Error())
	})

	t.Run("Session expired", func(t *testing.T) {
		mockSessionStorage.
			On("GetSessionByRefreshToken", ctx, refreshToken).
			Once().
			Return(entity.Session{
				UserID:        sessionReqData.UserID,
				AppID:         sessionReqData.AppID,
				DeviceID:      "test-device-id",
				RefreshToken:  refreshToken,
				LastVisitedAt: time.Now(),
				ExpiresAt:     time.Now().Add(-7 * 24 * time.Hour),
			}, nil)

		session, err := sessionService.GetSessionByRefreshToken(ctx, refreshToken)
		require.Empty(t, session)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrSessionExpired.Error())
	})
}

func TestGetUserDeviceID(t *testing.T) {
	mockSessionStorage := new(mocks.Storage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()
	sessionReqData := entity.SessionRequestData{
		UserID: "test-user-id",
		AppID:  "test-app-id",
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: "test-user-agent",
			IP:        "test-ip",
		},
	}

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("test-device-id", nil)

		deviceID, err := sessionService.GetUserDeviceID(ctx, sessionReqData)
		require.NoError(t, err)
		require.Equal(t, "test-device-id", deviceID)
	})

	t.Run("Error in GetUserDeviceID", func(t *testing.T) {
		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("", errors.New("failed to get device id"))

		deviceID, err := sessionService.GetUserDeviceID(ctx, sessionReqData)
		require.Empty(t, deviceID)
		require.Error(t, err)
	})

	t.Run("Error in GetUserDeviceID – user device not found", func(t *testing.T) {
		mockSessionStorage.
			On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Once().
			Return("", storage.ErrUserDeviceNotFound)

		deviceID, err := sessionService.GetUserDeviceID(ctx, sessionReqData)
		require.Empty(t, deviceID)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrUserDeviceNotFound.Error())
	})
}

func TestDeleteRefreshToken(t *testing.T) {
	mockSessionStorage := new(mocks.Storage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.
			On("DeleteRefreshToken", ctx, "test-refresh-token").
			Once().
			Return(nil)

		err := sessionService.DeleteRefreshToken(ctx, "test-refresh-token")
		require.NoError(t, err)
	})

	t.Run("Error in DeleteRefreshToken", func(t *testing.T) {
		mockSessionStorage.
			On("DeleteRefreshToken", ctx, "test-refresh-token").
			Once().
			Return(errors.New("failed to delete refresh token"))

		err := sessionService.DeleteRefreshToken(ctx, "test-refresh-token")
		require.Error(t, err)
	})
}

func TestDeleteSession(t *testing.T) {
	mockSessionStorage := new(mocks.Storage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()
	sessionReqData := entity.SessionRequestData{
		UserID:   "test-user-id",
		DeviceID: "test-device-id",
		AppID:    "test-app-id",
	}

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.
			On("DeleteSession", ctx, entity.Session{
				UserID:   sessionReqData.UserID,
				DeviceID: sessionReqData.DeviceID,
				AppID:    sessionReqData.AppID,
			}).
			Once().
			Return(nil)

		err := sessionService.DeleteSession(ctx, sessionReqData)
		require.NoError(t, err)
	})

	t.Run("Error in DeleteSession", func(t *testing.T) {
		mockSessionStorage.
			On("DeleteSession", ctx, entity.Session{
				UserID:   sessionReqData.UserID,
				DeviceID: sessionReqData.DeviceID,
				AppID:    sessionReqData.AppID,
			}).
			Once().
			Return(errors.New("failed to delete session"))

		err := sessionService.DeleteSession(ctx, sessionReqData)
		require.Error(t, err)
	})
}

func TestDeleteUserSessions(t *testing.T) {
	mockSessionStorage := new(mocks.Storage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()
	user := entity.User{
		ID: "test-user-id",
	}

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.
			On("DeleteAllSessions", ctx, user.ID, "").
			Once().
			Return(nil)

		err := sessionService.DeleteUserSessions(ctx, user)
		require.NoError(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in DeleteAllSessions", func(t *testing.T) {
		mockSessionStorage.
			On("DeleteAllSessions", ctx, user.ID, "").
			Once().
			Return(errors.New("failed to delete all sessions"))

		err := sessionService.DeleteUserSessions(ctx, user)
		require.Error(t, err)
	})
}
