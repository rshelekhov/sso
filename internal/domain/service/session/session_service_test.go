package session_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/domain/service/session/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSessionService_CreateSession(t *testing.T) {
	ctx := context.Background()

	userID := "test-user-id"
	clientID := "test-app-id"
	userAgent := "test-user-agent"
	ip := "127.0.0.1"
	issuer := "test-issuer"
	accessTokenTTL := 15 * time.Minute
	refreshTokenTTL := 7 * 24 * time.Hour
	kid := "test-kid"
	accessTokenStr := "test-access-token"
	refreshTokenStr := "test-refresh-token"
	cookieDomain := "test-cookie-domain"
	cookiePath := "test-cookie-path"
	deviceID := "test-device-id"

	sessionReqData := entity.SessionRequestData{
		UserID:   userID,
		ClientID: clientID,
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: userAgent,
			IP:        ip,
		},
	}

	expectedTokens := entity.SessionTokens{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		Domain:       "test-cookie-domain",
		Path:         "test-cookie-path",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
		HTTPOnly:     true,
	}

	tests := []struct {
		name         string
		reqData      entity.SessionRequestData
		mockBehavior func(
			jwtManager *mocks.JWTManager,
			sessionStorage *mocks.SessionStorage,
			deviceStorage *mocks.DeviceStorage,
		)
		expectedError  error
		expectedTokens entity.SessionTokens
	}{
		{
			name:    "Success",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				jwtManager.EXPECT().Kid(sessionReqData.ClientID).
					Once().
					Return(kid, nil)

				jwtManager.EXPECT().NewAccessToken(sessionReqData.ClientID, kid, mock.Anything).
					Once().
					Return(accessTokenStr, nil)

				jwtManager.EXPECT().NewRefreshToken(sessionReqData.ClientID).
					Once().
					Return(refreshTokenStr)

				jwtManager.EXPECT().RefreshTokenCookieDomain().
					Once().
					Return(cookieDomain)

				jwtManager.EXPECT().RefreshTokenCookiePath().
					Once().
					Return(cookiePath)

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return(deviceID, nil)

				sessionStorage.EXPECT().CreateSession(ctx, mock.Anything).
					Once().
					Return(nil)

				deviceStorage.EXPECT().UpdateLastVisitedAt(ctx, mock.Anything).
					Once().
					Return(nil)
			},
			expectedError:  nil,
			expectedTokens: expectedTokens,
		},
		{
			name:    "Success — register new device",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				jwtManager.EXPECT().Kid(sessionReqData.ClientID).
					Once().
					Return(kid, nil)

				jwtManager.EXPECT().NewAccessToken(sessionReqData.ClientID, kid, mock.Anything).
					Once().
					Return(accessTokenStr, nil)

				jwtManager.EXPECT().NewRefreshToken(sessionReqData.ClientID).
					Once().
					Return(refreshTokenStr)

				jwtManager.EXPECT().RefreshTokenCookieDomain().
					Once().
					Return(cookieDomain)

				jwtManager.EXPECT().RefreshTokenCookiePath().
					Once().
					Return(cookiePath)

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return("", storage.ErrUserDeviceNotFound)

				deviceStorage.EXPECT().RegisterDevice(ctx, mock.Anything).
					Once().
					Return(nil)

				sessionStorage.EXPECT().CreateSession(ctx, mock.Anything).
					Once().
					Return(nil)

				deviceStorage.EXPECT().UpdateLastVisitedAt(ctx, mock.Anything).
					Once().
					Return(nil)
			},
			expectedError:  nil,
			expectedTokens: expectedTokens,
		},
		{
			name:    "Failed to get device ID",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return("", errors.New("failed to get device ID"))
			},
			expectedError:  domain.ErrFailedToGetDeviceID,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to get key ID",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				jwtManager.EXPECT().Kid(sessionReqData.ClientID).
					Once().
					Return("", domain.ErrFailedToGetKeyID)

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return(deviceID, nil)
			},
			expectedError:  domain.ErrFailedToGetKeyID,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to create access token",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				jwtManager.EXPECT().Kid(sessionReqData.ClientID).
					Once().
					Return(kid, nil)

				jwtManager.EXPECT().NewAccessToken(sessionReqData.ClientID, kid, mock.Anything).
					Once().Return("", errors.New("jwt manager error"))

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return(deviceID, nil)
			},
			expectedError:  domain.ErrFailedToCreateAccessToken,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to create session",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				jwtManager.EXPECT().Kid(sessionReqData.ClientID).
					Once().
					Return(kid, nil)

				jwtManager.EXPECT().NewAccessToken(sessionReqData.ClientID, kid, mock.Anything).
					Once().
					Return(accessTokenStr, nil)

				jwtManager.EXPECT().NewRefreshToken(sessionReqData.ClientID).
					Once().
					Return(refreshTokenStr)

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return(deviceID, nil)

				sessionStorage.EXPECT().CreateSession(ctx, mock.Anything).
					Once().Return(fmt.Errorf("session storage error"))
			},
			expectedError:  domain.ErrFailedToCreateUserSession,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to update last visited at",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				jwtManager.EXPECT().Kid(sessionReqData.ClientID).
					Once().
					Return(kid, nil)

				jwtManager.EXPECT().NewAccessToken(sessionReqData.ClientID, kid, mock.Anything).
					Once().
					Return(accessTokenStr, nil)

				jwtManager.EXPECT().NewRefreshToken(sessionReqData.ClientID).
					Once().
					Return(refreshTokenStr)

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return(deviceID, nil)

				sessionStorage.EXPECT().CreateSession(ctx, mock.Anything).
					Once().Return(nil)

				deviceStorage.EXPECT().UpdateLastVisitedAt(ctx, mock.Anything).
					Once().
					Return(errors.New("session storage error"))
			},
			expectedError:  domain.ErrFailedToUpdateLastVisitedAt,
			expectedTokens: entity.SessionTokens{},
		},
		{
			name:    "Failed to register device",
			reqData: sessionReqData,
			mockBehavior: func(
				jwtManager *mocks.JWTManager,
				sessionStorage *mocks.SessionStorage,
				deviceStorage *mocks.DeviceStorage,
			) {
				jwtManager.EXPECT().Issuer().
					Once().
					Return(issuer)

				jwtManager.EXPECT().AccessTokenTTL().
					Once().
					Return(accessTokenTTL)

				jwtManager.EXPECT().RefreshTokenTTL().
					Once().
					Return(refreshTokenTTL)

				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return("", storage.ErrUserDeviceNotFound)

				deviceStorage.EXPECT().RegisterDevice(ctx, mock.Anything).
					Once().
					Return(fmt.Errorf("device storage error"))
			},
			expectedError:  domain.ErrFailedToRegisterDevice,
			expectedTokens: entity.SessionTokens{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtManager := mocks.NewJWTManager(t)
			sessionStorage := mocks.NewSessionStorage(t)
			deviceStorage := mocks.NewDeviceStorage(t)

			tt.mockBehavior(jwtManager, sessionStorage, deviceStorage)

			service := session.NewService(jwtManager, sessionStorage, deviceStorage, &mocks.NoOpMetricsRecorder{})

			tokens, err := service.CreateSession(ctx, tt.reqData)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedTokens.AccessToken, tokens.AccessToken)
				assert.Equal(t, tt.expectedTokens.RefreshToken, tokens.RefreshToken)
				assert.Equal(t, tt.expectedTokens.Domain, tokens.Domain)
				assert.Equal(t, tt.expectedTokens.Path, tokens.Path)
				assert.WithinDuration(t, tt.expectedTokens.ExpiresAt, tokens.ExpiresAt, time.Second)
				assert.Equal(t, tt.expectedTokens.HTTPOnly, tokens.HTTPOnly)
			}
		})
	}
}

func TestSessionService_GetSessionByRefreshToken(t *testing.T) {
	ctx := context.Background()
	refreshToken := "test-refresh-token"

	tests := []struct {
		name          string
		refreshToken  string
		mockBehavior  func(sessionStorage *mocks.SessionStorage)
		expectedError error
		wantSession   bool
	}{
		{
			name:         "Success",
			refreshToken: refreshToken,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().GetSessionByRefreshToken(ctx, refreshToken).
					Once().
					Return(entity.Session{
						UserID:        "test-user-id",
						DeviceID:      "test-device-id",
						RefreshToken:  refreshToken,
						LastVisitedAt: time.Now(),
						ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
					}, nil)
			},
			expectedError: nil,
			wantSession:   true,
		},
		{
			name:         "Session not found",
			refreshToken: refreshToken,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().GetSessionByRefreshToken(ctx, refreshToken).
					Once().
					Return(entity.Session{}, storage.ErrSessionNotFound)
			},
			expectedError: domain.ErrSessionNotFound,
			wantSession:   false,
		},
		{
			name:         "Session expired",
			refreshToken: refreshToken,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().GetSessionByRefreshToken(ctx, refreshToken).
					Once().
					Return(entity.Session{
						UserID:        "test-user-id",
						DeviceID:      "test-device-id",
						RefreshToken:  refreshToken,
						LastVisitedAt: time.Now(),
						ExpiresAt:     time.Now().Add(-7 * 24 * time.Hour),
					}, nil)
			},
			expectedError: domain.ErrSessionExpired,
			wantSession:   false,
		},
		{
			name:         "Failed to get session",
			refreshToken: refreshToken,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().GetSessionByRefreshToken(ctx, refreshToken).
					Once().
					Return(entity.Session{}, errors.New("failed to get session"))
			},
			expectedError: errors.New("failed to get session"),
			wantSession:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStorage := mocks.NewSessionStorage(t)
			tt.mockBehavior(sessionStorage)

			service := session.NewService(nil, sessionStorage, nil, &mocks.NoOpMetricsRecorder{})

			session, err := service.GetSessionByRefreshToken(ctx, tt.refreshToken)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			if tt.wantSession {
				assert.NotEmpty(t, session)
			} else {
				assert.Empty(t, session)
			}
		})
	}
}

func TestSessionService_GetUserDeviceID(t *testing.T) {
	ctx := context.Background()
	sessionReqData := entity.SessionRequestData{
		UserID: "test-user-id",
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: "test-user-agent",
		},
	}

	tests := []struct {
		name          string
		reqData       entity.SessionRequestData
		mockBehavior  func(deviceStorage *mocks.DeviceStorage)
		expectedError error
		wantDeviceID  bool
	}{
		{
			name:    "Success",
			reqData: sessionReqData,
			mockBehavior: func(deviceStorage *mocks.DeviceStorage) {
				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return("test-device-id", nil)
			},
			expectedError: nil,
			wantDeviceID:  true,
		},
		{
			name:    "Device not found",
			reqData: sessionReqData,
			mockBehavior: func(deviceStorage *mocks.DeviceStorage) {
				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return("", storage.ErrUserDeviceNotFound)
			},
			expectedError: domain.ErrUserDeviceNotFound,
			wantDeviceID:  false,
		},
		{
			name:    "Failed to get device ID",
			reqData: sessionReqData,
			mockBehavior: func(deviceStorage *mocks.DeviceStorage) {
				deviceStorage.EXPECT().GetUserDeviceID(ctx, sessionReqData.UserID, sessionReqData.UserDevice.UserAgent).
					Once().
					Return("", errors.New("failed to get device id"))
			},
			expectedError: errors.New("failed to get device id"),
			wantDeviceID:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceStorage := mocks.NewDeviceStorage(t)
			tt.mockBehavior(deviceStorage)

			service := session.NewService(nil, nil, deviceStorage, &mocks.NoOpMetricsRecorder{})

			deviceID, err := service.GetUserDeviceID(ctx, tt.reqData.UserID, tt.reqData.UserDevice.UserAgent)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			if tt.wantDeviceID {
				assert.NotEmpty(t, deviceID)
			} else {
				assert.Empty(t, deviceID)
			}
		})
	}
}

func TestSessionService_DeleteRefreshToken(t *testing.T) {
	ctx := context.Background()
	refreshToken := "test-refresh-token"

	tests := []struct {
		name          string
		refreshToken  string
		mockBehavior  func(sessionStorage *mocks.SessionStorage)
		expectedError error
	}{
		{
			name:         "Success",
			refreshToken: refreshToken,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().DeleteRefreshToken(ctx, refreshToken).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "Failed to delete refresh token",
			refreshToken: refreshToken,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().DeleteRefreshToken(ctx, refreshToken).
					Once().
					Return(errors.New("failed to delete refresh token"))
			},
			expectedError: errors.New("failed to delete refresh token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStorage := mocks.NewSessionStorage(t)
			tt.mockBehavior(sessionStorage)

			service := session.NewService(nil, sessionStorage, nil, &mocks.NoOpMetricsRecorder{})

			err := service.DeleteRefreshToken(ctx, tt.refreshToken)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSessionService_DeleteSession(t *testing.T) {
	ctx := context.Background()
	sessionReqData := entity.SessionRequestData{
		UserID:   "test-user-id",
		DeviceID: "test-device-id",
	}

	tests := []struct {
		name          string
		reqData       entity.SessionRequestData
		mockBehavior  func(sessionStorage *mocks.SessionStorage)
		expectedError error
	}{
		{
			name:    "Success",
			reqData: sessionReqData,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().DeleteSession(ctx, entity.Session{
					UserID:   sessionReqData.UserID,
					DeviceID: sessionReqData.DeviceID,
				}).
					Once().
					Return(entity.SessionMeta{}, nil)
			},
			expectedError: nil,
		},
		{
			name:    "Failed to delete session",
			reqData: sessionReqData,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().DeleteSession(ctx, entity.Session{
					UserID:   sessionReqData.UserID,
					DeviceID: sessionReqData.DeviceID,
				}).
					Once().
					Return(entity.SessionMeta{}, errors.New("failed to delete session"))
			},
			expectedError: errors.New("failed to delete session"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStorage := mocks.NewSessionStorage(t)
			tt.mockBehavior(sessionStorage)

			service := session.NewService(nil, sessionStorage, nil, &mocks.NoOpMetricsRecorder{})

			err := service.DeleteSession(ctx, tt.reqData)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSessionService_DeleteUserSessions(t *testing.T) {
	ctx := context.Background()
	user := entity.User{
		ID: "test-user-id",
	}

	tests := []struct {
		name          string
		user          entity.User
		mockBehavior  func(sessionStorage *mocks.SessionStorage)
		expectedError error
	}{
		{
			name: "Success",
			user: user,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().DeleteAllSessions(ctx, user.ID).
					Once().
					Return([]entity.SessionMeta{}, nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed to delete user sessions",
			user: user,
			mockBehavior: func(sessionStorage *mocks.SessionStorage) {
				sessionStorage.EXPECT().DeleteAllSessions(ctx, user.ID).
					Once().
					Return([]entity.SessionMeta{}, errors.New("failed to delete user sessions"))
			},
			expectedError: errors.New("failed to delete user sessions"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStorage := mocks.NewSessionStorage(t)
			tt.mockBehavior(sessionStorage)

			service := session.NewService(nil, sessionStorage, nil, &mocks.NoOpMetricsRecorder{})

			err := service.DeleteUserSessions(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSessionService_DeleteUserDevices(t *testing.T) {
	ctx := context.Background()
	user := entity.User{
		ID: "test-user-id",
	}

	tests := []struct {
		name          string
		user          entity.User
		mockBehavior  func(deviceStorage *mocks.DeviceStorage)
		expectedError error
	}{
		{
			name: "Success",
			user: user,
			mockBehavior: func(deviceStorage *mocks.DeviceStorage) {
				deviceStorage.EXPECT().DeleteAllUserDevices(ctx, user.ID).
					Once().
					Return(1, nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed to delete user devices",
			user: user,
			mockBehavior: func(deviceStorage *mocks.DeviceStorage) {
				deviceStorage.EXPECT().DeleteAllUserDevices(ctx, user.ID).
					Once().
					Return(0, errors.New("failed to delete user devices"))
			},
			expectedError: errors.New("failed to delete user devices"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceStorage := mocks.NewDeviceStorage(t)
			tt.mockBehavior(deviceStorage)

			service := session.NewService(nil, nil, deviceStorage, &mocks.NoOpMetricsRecorder{})

			err := service.DeleteUserDevices(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
