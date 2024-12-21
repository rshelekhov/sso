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
	mockSessionStorage := new(mocks.SessionStorage)

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
		mockJWTManager.ExpectedCalls = nil
		mockSessionStorage.ExpectedCalls = nil

		mockJWTManager.On("Issuer").
			Return("test-issuer")
		mockJWTManager.On("AccessTokenTTL").
			Return(15 * time.Minute)
		mockJWTManager.On("RefreshTokenTTL").
			Return(7 * 24 * time.Hour)
		mockJWTManager.On("Kid", sessionReqData.AppID).
			Return("test-kid", nil)
		mockJWTManager.On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).
			Return("test-access-token", nil)
		mockJWTManager.On("NewRefreshToken").
			Return("test-refresh-token")
		mockJWTManager.On("RefreshTokenCookieDomain").
			Return("test-cookie-domain")
		mockJWTManager.On("RefreshTokenCookiePath").
			Return("test-cookie-path")

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("test-device-id", nil)
		mockSessionStorage.On("CreateUserSession", ctx, mock.Anything).
			Return(nil)
		mockSessionStorage.On("UpdateLastVisitedAt", ctx, mock.Anything).
			Return(nil)

		sessionReqData.DeviceID = "test-device-id"
		expectedTokens := entity.SessionTokens{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			Domain:       "",
			Path:         "",
			ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
			HTTPOnly:     true,
		}

		tokens, err := sessionService.CreateUserSession(ctx, sessionReqData)
		require.NoError(t, err)
		require.Equal(t, expectedTokens.AccessToken, tokens.AccessToken)
		require.Equal(t, expectedTokens.RefreshToken, tokens.RefreshToken)

		mockJWTManager.AssertExpectations(t)
		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in getOrRegisterDeviceID", func(t *testing.T) {
		mockJWTManager.ExpectedCalls = nil
		mockSessionStorage.ExpectedCalls = nil

		mockJWTManager.On("Issuer").Return("test-issuer")
		mockJWTManager.On("AccessTokenTTL").Return(15 * time.Minute)
		mockJWTManager.On("RefreshTokenTTL").Return(7 * 24 * time.Hour)

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("", errors.New("device not found"))

		_, err := sessionService.CreateUserSession(ctx, sessionReqData)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToGetDeviceID.Error())

		mockJWTManager.AssertExpectations(t)
		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in getOrRegisterDeviceID – failed to register device", func(t *testing.T) {
		mockJWTManager.ExpectedCalls = nil
		mockSessionStorage.ExpectedCalls = nil

		device := entity.NewUserDevice(sessionReqData)

		mockJWTManager.On("Issuer").Return("test-issuer")
		mockJWTManager.On("AccessTokenTTL").Return(15 * time.Minute)
		mockJWTManager.On("RefreshTokenTTL").Return(7 * 24 * time.Hour)

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("", storage.ErrUserDeviceNotFound)
		mockSessionStorage.On("RegisterDevice", ctx, mock.MatchedBy(func(d entity.UserDevice) bool {
			return d.UserID == device.UserID &&
				d.AppID == device.AppID &&
				d.UserAgent == device.UserAgent &&
				d.IP == device.IP &&
				d.Detached == device.Detached
		})).Return(errors.New("failed to register device"))

		_, err := sessionService.CreateUserSession(ctx, sessionReqData)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToRegisterDevice.Error())

		mockJWTManager.AssertExpectations(t)
		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in createTokens – failed to get keyID", func(t *testing.T) {
		mockJWTManager.ExpectedCalls = nil
		mockSessionStorage.ExpectedCalls = nil

		mockJWTManager.On("Issuer").Return("test-issuer")
		mockJWTManager.On("AccessTokenTTL").Return(15 * time.Minute)
		mockJWTManager.On("RefreshTokenTTL").Return(7 * 24 * time.Hour)
		mockJWTManager.On("Kid", sessionReqData.AppID).Return("", domain.ErrFailedToGetKeyID)

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("test-device-id", nil)

		_, err := sessionService.CreateUserSession(ctx, sessionReqData)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToGetKeyID.Error())

		mockJWTManager.AssertExpectations(t)
		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in createTokens – failed to create access token", func(t *testing.T) {
		mockJWTManager.ExpectedCalls = nil
		mockSessionStorage.ExpectedCalls = nil

		mockJWTManager.On("Issuer").Return("test-issuer")
		mockJWTManager.On("AccessTokenTTL").Return(15 * time.Minute)
		mockJWTManager.On("RefreshTokenTTL").Return(7 * 24 * time.Hour)
		mockJWTManager.On("Kid", sessionReqData.AppID).Return("test-kid", nil)

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("test-device-id", nil)

		mockJWTManager.On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).
			Return("", errors.New("failed to create access token"))

		_, err := sessionService.CreateUserSession(ctx, sessionReqData)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToCreateAccessToken.Error())

		mockJWTManager.AssertExpectations(t)
		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in saveSession – failed to create user session", func(t *testing.T) {
		mockJWTManager.ExpectedCalls = nil
		mockSessionStorage.ExpectedCalls = nil

		mockJWTManager.On("Issuer").Return("test-issuer")
		mockJWTManager.On("AccessTokenTTL").Return(15 * time.Minute)
		mockJWTManager.On("RefreshTokenTTL").Return(7 * 24 * time.Hour)
		mockJWTManager.On("Kid", sessionReqData.AppID).Return("test-kid", nil)
		mockJWTManager.On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).Return("test-access-token", nil)
		mockJWTManager.On("NewRefreshToken").Return("test-refresh-token")

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("test-device-id", nil)
		mockSessionStorage.On("CreateUserSession", ctx, mock.Anything).Return(errors.New("failed to create session"))

		_, err := sessionService.CreateUserSession(ctx, sessionReqData)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToCreateUserSession.Error())

		mockJWTManager.AssertExpectations(t)
		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in saveSession – failed to update last visited at", func(t *testing.T) {
		mockJWTManager.ExpectedCalls = nil
		mockSessionStorage.ExpectedCalls = nil

		mockJWTManager.On("Issuer").Return("test-issuer")
		mockJWTManager.On("AccessTokenTTL").Return(15 * time.Minute)
		mockJWTManager.On("RefreshTokenTTL").Return(7 * 24 * time.Hour)
		mockJWTManager.On("Kid", sessionReqData.AppID).Return("test-kid", nil)
		mockJWTManager.On("NewAccessToken", sessionReqData.AppID, "test-kid", mock.Anything).Return("test-access-token", nil)
		mockJWTManager.On("NewRefreshToken").Return("test-refresh-token")

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("test-device-id", nil)
		mockSessionStorage.On("CreateUserSession", ctx, mock.Anything).Return(nil)
		mockSessionStorage.On("UpdateLastVisitedAt", ctx, mock.Anything).Return(errors.New("failed to update last visited at"))

		_, err := sessionService.CreateUserSession(ctx, sessionReqData)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrFailedToUpdateLastVisitedAt.Error())

		mockJWTManager.AssertExpectations(t)
		mockSessionStorage.AssertExpectations(t)
	})
}

func TestCheckSessionAndDevice(t *testing.T) {
	mockSessionStorage := new(mocks.SessionStorage)

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
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetSessionByRefreshToken", ctx, refreshToken).
			Return(entity.Session{
				UserID:        sessionReqData.UserID,
				AppID:         sessionReqData.AppID,
				DeviceID:      "test-device-id",
				RefreshToken:  refreshToken,
				LastVisitedAt: time.Now(),
				ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
			}, nil)
		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("test-device-id", nil)

		_, err := sessionService.CheckSessionAndDevice(ctx, refreshToken, sessionReqData.UserDevice)
		require.NoError(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in GetSessionByRefreshToken", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetSessionByRefreshToken", ctx, refreshToken).
			Return(entity.Session{}, errors.New("failed to get session"))

		_, err := sessionService.CheckSessionAndDevice(ctx, refreshToken, sessionReqData.UserDevice)
		require.Error(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in GetSessionByRefreshToken – session not found", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetSessionByRefreshToken", ctx, refreshToken).
			Return(entity.Session{}, storage.ErrSessionNotFound)

		_, err := sessionService.CheckSessionAndDevice(ctx, refreshToken, sessionReqData.UserDevice)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrSessionNotFound.Error())

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Session expired", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetSessionByRefreshToken", ctx, refreshToken).
			Return(entity.Session{
				UserID:        sessionReqData.UserID,
				AppID:         sessionReqData.AppID,
				DeviceID:      "test-device-id",
				RefreshToken:  refreshToken,
				LastVisitedAt: time.Now(),
				ExpiresAt:     time.Now().Add(-7 * 24 * time.Hour),
			}, nil)

		_, err := sessionService.CheckSessionAndDevice(ctx, refreshToken, sessionReqData.UserDevice)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrSessionExpired.Error())

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in GetUserDeviceID", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetSessionByRefreshToken", ctx, refreshToken).
			Return(entity.Session{
				UserID:        sessionReqData.UserID,
				AppID:         sessionReqData.AppID,
				DeviceID:      "test-device-id",
				RefreshToken:  refreshToken,
				LastVisitedAt: time.Now(),
				ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
			}, nil)
		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("", errors.New("failed to get device id"))

		_, err := sessionService.CheckSessionAndDevice(ctx, refreshToken, sessionReqData.UserDevice)
		require.Error(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in GetUserDeviceID – user device not found", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetSessionByRefreshToken", ctx, refreshToken).
			Return(entity.Session{
				UserID:        sessionReqData.UserID,
				AppID:         sessionReqData.AppID,
				DeviceID:      "test-device-id",
				RefreshToken:  refreshToken,
				LastVisitedAt: time.Now(),
				ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
			}, nil)
		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("", storage.ErrUserDeviceNotFound)

		_, err := sessionService.CheckSessionAndDevice(ctx, refreshToken, sessionReqData.UserDevice)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrUserDeviceNotFound.Error())

		mockSessionStorage.AssertExpectations(t)
	})
}

func TestGetUserDeviceID(t *testing.T) {
	mockSessionStorage := new(mocks.SessionStorage)

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
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("test-device-id", nil)

		deviceID, err := sessionService.GetUserDeviceID(ctx, sessionReqData)
		require.NoError(t, err)
		require.Equal(t, "test-device-id", deviceID)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in GetUserDeviceID", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("", errors.New("failed to get device id"))

		_, err := sessionService.GetUserDeviceID(ctx, sessionReqData)
		require.Error(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in GetUserDeviceID – user device not found", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("GetUserDeviceID", ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
			Return("", storage.ErrUserDeviceNotFound)

		_, err := sessionService.GetUserDeviceID(ctx, sessionReqData)
		require.Error(t, err)
		require.Contains(t, err.Error(), domain.ErrUserDeviceNotFound.Error())

		mockSessionStorage.AssertExpectations(t)
	})
}

func TestDeleteRefreshToken(t *testing.T) {
	mockSessionStorage := new(mocks.SessionStorage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("DeleteRefreshToken", ctx, "test-refresh-token").
			Return(nil)

		err := sessionService.DeleteRefreshToken(ctx, "test-refresh-token")
		require.NoError(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in DeleteRefreshToken", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("DeleteRefreshToken", ctx, "test-refresh-token").
			Return(errors.New("failed to delete refresh token"))

		err := sessionService.DeleteRefreshToken(ctx, "test-refresh-token")
		require.Error(t, err)

		mockSessionStorage.AssertExpectations(t)
	})
}

func TestDeleteSession(t *testing.T) {
	mockSessionStorage := new(mocks.SessionStorage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()
	sessionReqData := entity.SessionRequestData{
		UserID:   "test-user-id",
		DeviceID: "test-device-id",
		AppID:    "test-app-id",
	}

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("DeleteSession", ctx, entity.Session{
			UserID:   sessionReqData.UserID,
			DeviceID: sessionReqData.DeviceID,
			AppID:    sessionReqData.AppID,
		}).Return(nil)

		err := sessionService.DeleteSession(ctx, sessionReqData)
		require.NoError(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in DeleteSession", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("DeleteSession", ctx, entity.Session{
			UserID:   sessionReqData.UserID,
			DeviceID: sessionReqData.DeviceID,
			AppID:    sessionReqData.AppID,
		}).Return(errors.New("failed to delete session"))

		err := sessionService.DeleteSession(ctx, sessionReqData)
		require.Error(t, err)

		mockSessionStorage.AssertExpectations(t)
	})
}

func TestDeleteUserSessions(t *testing.T) {
	mockSessionStorage := new(mocks.SessionStorage)

	sessionService := NewService(nil, mockSessionStorage)

	ctx := context.Background()
	user := entity.User{
		ID: "test-user-id",
	}

	t.Run("Success", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("DeleteAllSessions", ctx, user.ID, "").
			Return(nil)

		err := sessionService.DeleteUserSessions(ctx, user)
		require.NoError(t, err)

		mockSessionStorage.AssertExpectations(t)
	})

	t.Run("Error in DeleteAllSessions", func(t *testing.T) {
		mockSessionStorage.ExpectedCalls = nil

		mockSessionStorage.On("DeleteAllSessions", ctx, user.ID, "").
			Return(errors.New("failed to delete all sessions"))

		err := sessionService.DeleteUserSessions(ctx, user)
		require.Error(t, err)

		mockSessionStorage.AssertExpectations(t)
	})
}
