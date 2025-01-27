package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type JWTManager interface {
	NewAccessToken(appID, kid string, additionalClaims map[string]interface{}) (string, error)
	NewRefreshToken() string
	Issuer() string
	AccessTokenTTL() time.Duration
	RefreshTokenTTL() time.Duration
	Kid(appID string) (string, error)
	RefreshTokenCookieDomain() string
	RefreshTokenCookiePath() string
}

type Storage interface {
	CreateSession(ctx context.Context, session entity.Session) error
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error)
	UpdateLastVisitedAt(ctx context.Context, session entity.Session) error
	DeleteRefreshToken(ctx context.Context, refreshToken string) error
	DeleteSession(ctx context.Context, session entity.Session) error
	DeleteAllSessions(ctx context.Context, userID, appID string) error
	GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error)
	RegisterDevice(ctx context.Context, device entity.UserDevice) error
}

type Session struct {
	jwtMgr  JWTManager
	storage Storage
}

func NewService(ts JWTManager, storage Storage) *Session {
	return &Session{
		jwtMgr:  ts,
		storage: storage,
	}
}

// TODO: Move sessions from Postgres to Redis

func (s *Session) CreateSession(ctx context.Context, sessionReqData entity.SessionRequestData) (entity.SessionTokens, error) {
	const method = "service.session.CreateSession"

	issuer, accessTokenTTL, refreshTokenTTL := s.prepareTokenConfig()

	deviceID, err := s.getOrRegisterDeviceID(ctx, sessionReqData)
	if err != nil {
		return entity.SessionTokens{}, fmt.Errorf("%s: %w", method, err)
	}

	sessionReqData.DeviceID = deviceID
	currentTime := time.Now()

	accessToken, refreshToken, err := s.createTokens(sessionReqData, issuer, accessTokenTTL, currentTime)
	if err != nil {
		return entity.SessionTokens{}, fmt.Errorf("%s: %w", method, err)
	}

	session := entity.NewSession(sessionReqData, refreshToken, refreshTokenTTL, currentTime)

	if err = s.saveSession(ctx, session); err != nil {
		return entity.SessionTokens{}, fmt.Errorf("%s: %w", method, err)
	}

	tokenData := s.prepareTokenResponse(accessToken, session)

	return tokenData, nil
}

func (s *Session) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	const method = "service.session.GetSessionByRefreshToken"

	session, err := s.storage.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, storage.ErrSessionNotFound) {
			return entity.Session{}, domain.ErrSessionNotFound
		}
		return entity.Session{}, fmt.Errorf("%s: %w", method, err)
	}

	if session.IsExpired() {
		return entity.Session{}, domain.ErrSessionExpired
	}

	return session, nil
}

func (s *Session) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	const method = "service.session.GetUserDeviceID"

	deviceID, err := s.storage.GetUserDeviceID(ctx, userID, userAgent)
	if err != nil {
		if errors.Is(err, storage.ErrUserDeviceNotFound) {
			return "", domain.ErrUserDeviceNotFound
		}
		return "", fmt.Errorf("%s: %w", method, err)
	}

	return deviceID, nil
}

func (s *Session) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	const method = "service.session.DeleteRefreshToken"

	if err := s.storage.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (s *Session) DeleteSession(ctx context.Context, sessionReqData entity.SessionRequestData) error {
	const method = "service.session.DeleteSession"

	if err := s.storage.DeleteSession(ctx, entity.Session{
		UserID:   sessionReqData.UserID,
		DeviceID: sessionReqData.DeviceID,
		AppID:    sessionReqData.AppID,
	}); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (s *Session) DeleteUserSessions(ctx context.Context, user entity.User) error {
	const method = "service.session.DeleteAllUserSessions"

	if err := s.storage.DeleteAllSessions(ctx, user.ID, user.AppID); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (s *Session) prepareTokenConfig() (issuer string, accessTokenTTL, refreshTokenTTL time.Duration) {
	issuer = s.jwtMgr.Issuer()
	accessTokenTTL = s.jwtMgr.AccessTokenTTL()
	refreshTokenTTL = s.jwtMgr.RefreshTokenTTL()

	return issuer, accessTokenTTL, refreshTokenTTL
}

func (s *Session) getOrRegisterDeviceID(ctx context.Context, session entity.SessionRequestData) (string, error) {
	deviceID, err := s.storage.GetUserDeviceID(ctx, session.UserID, session.UserDevice.UserAgent)
	if err != nil {
		if errors.Is(err, storage.ErrUserDeviceNotFound) {
			return s.registerDevice(ctx, session)
		}
		return "", fmt.Errorf("%w: %w", domain.ErrFailedToGetDeviceID, err)
	}

	return deviceID, nil
}

func (s *Session) registerDevice(ctx context.Context, session entity.SessionRequestData) (string, error) {
	userDevice := entity.NewUserDevice(session)

	if err := s.storage.RegisterDevice(ctx, userDevice); err != nil {
		return "", fmt.Errorf("%w: %w", domain.ErrFailedToRegisterDevice, err)
	}

	return userDevice.ID, nil
}

func (s *Session) createTokens(
	session entity.SessionRequestData,
	issuer string,
	accessTokenTTL time.Duration,
	currentTime time.Time,
) (
	accessToken string,
	refreshToken string,
	err error,
) {
	kid, err := s.jwtMgr.Kid(session.AppID)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", domain.ErrFailedToGetKeyID, err)
	}

	additionalClaims := map[string]interface{}{
		domain.IssuerKey:       issuer,
		domain.UserIDKey:       session.UserID,
		domain.AppIDKey:        session.AppID,
		domain.ExpirationAtKey: currentTime.Add(accessTokenTTL).Unix(),
	}

	accessToken, err = s.jwtMgr.NewAccessToken(session.AppID, kid, additionalClaims)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", domain.ErrFailedToCreateAccessToken, err)
	}

	refreshToken = s.jwtMgr.NewRefreshToken()

	return accessToken, refreshToken, nil
}

func (s *Session) saveSession(ctx context.Context, session entity.Session) error {
	if err := s.storage.CreateSession(ctx, session); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToCreateUserSession, err)
	}

	if err := s.storage.UpdateLastVisitedAt(ctx, session); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrFailedToUpdateLastVisitedAt, err)
	}

	return nil
}

func (s *Session) prepareTokenResponse(accessToken string, session entity.Session) entity.SessionTokens {
	cookieDomain := s.jwtMgr.RefreshTokenCookieDomain()
	path := s.jwtMgr.RefreshTokenCookiePath()

	return entity.SessionTokens{
		AccessToken:  accessToken,
		RefreshToken: session.RefreshToken,
		Domain:       cookieDomain,
		Path:         path,
		ExpiresAt:    session.ExpiresAt,
		HTTPOnly:     true,
	}
}
