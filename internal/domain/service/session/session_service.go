package session

import (
	"context"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/segmentio/ksuid"
	"time"
)

type Service interface {
	CreateUserSession(ctx context.Context, user entity.User, userDeviceRequest entity.UserDeviceRequestData) (entity.SessionTokens, error)
	CheckSessionAndDevice(ctx context.Context, refreshToken string, userDevice entity.UserDeviceRequestData) (entity.Session, error)
	GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
	DeleteRefreshToken(ctx context.Context, refreshToken string) error
	DeleteSession(ctx context.Context, userID, deviceID, appID string) error
	DeleteUserSessions(ctx context.Context, user entity.User) error
}

type Storage interface {
	CreateUserSession(ctx context.Context, session entity.Session) error
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error)
	UpdateLastVisitedAt(ctx context.Context, deviceID, appID string, latestVisitedAt time.Time) error
	DeleteRefreshToken(ctx context.Context, refreshToken string) error
	DeleteSession(ctx context.Context, userID, deviceID, appID string) error
	DeleteAllSessions(ctx context.Context, userID, appID string) error
	GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
	RegisterDevice(ctx context.Context, device entity.UserDevice) error
}

type Session struct {
	storage      Storage
	tokenService token.JWTManager
}

func NewService(storage Storage, ts token.JWTManager) *Session {
	return &Session{
		storage:      storage,
		tokenService: ts,
	}
}

// TODO: Move sessions from Postgres to Redis

// CreateUserSession creates new user session in the system and returns jwtoken
func (s *Session) CreateUserSession(
	ctx context.Context,
	user entity.User,
	userDevice entity.UserDeviceRequestData,
) (
	entity.SessionTokens,
	error,
) {
	const method = "service.session.CreateUserSession"

	issuer, accessTokenTTL, refreshTokenTTL, err := s.prepareTokenConfig()
	if err != nil {
		return entity.SessionTokens{}, fmt.Errorf("%s: %w", method, err)
	}

	deviceID, err := s.getOrRegisterDeviceID(ctx, user.ID, user.AppID, userDevice)
	if err != nil {
		return entity.SessionTokens{}, fmt.Errorf("%s: %w", method, err)
	}

	currentTime := time.Now()

	accessToken, refreshToken, err := s.createTokens(user, issuer, accessTokenTTL, currentTime)
	if err != nil {
		return entity.SessionTokens{}, fmt.Errorf("%s: %w", method, err)
	}

	if err = s.saveSession(ctx, user, deviceID, refreshToken, refreshTokenTTL, currentTime); err != nil {
		return entity.SessionTokens{}, fmt.Errorf("%s: %w", method, err)
	}

	tokenData, err := s.prepareTokenResponse(accessToken, refreshToken, refreshTokenTTL, currentTime)

	return tokenData, nil
}

func (s *Session) CheckSessionAndDevice(ctx context.Context, refreshToken string, userDevice entity.UserDeviceRequestData) (entity.Session, error) {
	session, err := s.storage.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, storage.ErrSessionNotFound) {
			return entity.Session{}, domain.ErrSessionNotFound
		}
		return entity.Session{}, err
	}

	if session.IsExpired() {
		return entity.Session{}, domain.ErrSessionExpired
	}

	_, err = s.storage.GetUserDeviceID(ctx, session.UserID, userDevice.UserAgent)
	if err != nil {
		if errors.Is(err, storage.ErrUserDeviceNotFound) {
			return entity.Session{}, domain.ErrUserDeviceNotFound
		}
		return entity.Session{}, err
	}

	return session, nil
}

func (s *Session) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	return s.storage.GetUserDeviceID(ctx, userID, userAgent)
}

func (s *Session) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	return s.storage.DeleteRefreshToken(ctx, refreshToken)
}

func (s *Session) DeleteSession(ctx context.Context, userID, deviceID, appID string) error {
	return s.storage.DeleteSession(ctx, userID, deviceID, appID)
}

func (s *Session) DeleteUserSessions(ctx context.Context, user entity.User) error {
	const method = "service.session.DeleteAllUserSessions"

	if err := s.storage.DeleteAllSessions(ctx, user.ID, user.AppID); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (s *Session) prepareTokenConfig() (string, time.Duration, time.Duration, error) {
	issuer := s.tokenService.Issuer()
	accessTokenTTL := s.tokenService.AccessTokenTTL()
	refreshTokenTTL := s.tokenService.RefreshTokenTTL()

	return issuer, accessTokenTTL, refreshTokenTTL, nil
}

func (s *Session) getOrRegisterDeviceID(ctx context.Context, userID, appID string, userDeviceRequest entity.UserDeviceRequestData) (string, error) {
	deviceID, err := s.storage.GetUserDeviceID(ctx, userID, userDeviceRequest.UserAgent)
	if err != nil {
		if errors.Is(err, storage.ErrUserDeviceNotFound) {
			return s.registerDevice(ctx, userID, appID, userDeviceRequest)
		}
		return "", fmt.Errorf("%w: %w", domain.ErrFailedToGetDeviceID, err)
	}

	return deviceID, nil
}

func (s *Session) registerDevice(ctx context.Context, userID, appID string, userDeviceRequest entity.UserDeviceRequestData) (string, error) {
	userDevice := entity.UserDevice{
		ID:            ksuid.New().String(),
		UserID:        userID,
		AppID:         appID,
		UserAgent:     userDeviceRequest.UserAgent,
		IP:            userDeviceRequest.IP,
		Detached:      false,
		LastVisitedAt: time.Now(),
	}

	if err := s.storage.RegisterDevice(ctx, userDevice); err != nil {
		return "", fmt.Errorf("%w: %w", domain.ErrFailedToRegisterDevice, err)
	}

	return userDevice.ID, nil
}

func (s *Session) createTokens(user entity.User, issuer string, accessTokenTTL time.Duration, currentTime time.Time) (string, string, error) {
	kid, err := s.tokenService.Kid(user.AppID)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", domain.ErrFailedToGetKeyID, err)
	}

	additionalClaims := map[string]interface{}{
		"issuer":        issuer,
		"user_id":       user.ID,
		"app_id":        user.AppID,
		"expiration_at": currentTime.Add(accessTokenTTL).Unix(),
	}

	accessToken, err := s.tokenService.NewAccessToken(user.AppID, kid, additionalClaims)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", domain.ErrFailedToCreateAccessToken, err)
	}

	refreshToken := s.tokenService.NewRefreshToken()

	return accessToken, refreshToken, nil
}

func (s *Session) saveSession(ctx context.Context, user entity.User, deviceID, refreshToken string, refreshTokenTTL time.Duration, currentTime time.Time) error {
	session := entity.Session{
		UserID:        user.ID,
		AppID:         user.AppID,
		DeviceID:      deviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: currentTime,
		ExpiresAt:     currentTime.Add(refreshTokenTTL),
	}

	if err := s.storage.CreateUserSession(ctx, session); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
	}

	if err := s.storage.UpdateLastVisitedAt(ctx, deviceID, user.AppID, session.LastVisitedAt); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToUpdateLastVisitedAt, err)
	}

	return nil
}

func (s *Session) prepareTokenResponse(accessToken, refreshToken string, refreshTokenTTL time.Duration, currentTime time.Time) (entity.SessionTokens, error) {

	cookieDomain := s.tokenService.GetRefreshTokenCookieDomain()
	path := s.tokenService.GetRefreshTokenCookiePath()

	return entity.SessionTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Domain:       cookieDomain,
		Path:         path,
		ExpiresAt:    currentTime.Add(refreshTokenTTL),
		HTTPOnly:     true,
	}, nil
}
