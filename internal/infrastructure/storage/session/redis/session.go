package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

const (
	sessionKeyPrefix      = "session:"
	deviceKeyPrefix       = "device:"
	refreshTokenKeyPrefix = "refresh_token:"
	revokedTokenKeyPrefix = "revoked_token:"
)

type SessionStorage struct {
	client          *redis.Client
	sessionTTL      time.Duration
	revokedTokenTTL time.Duration
}

func NewSessionStorage(redisConn *storage.RedisConnection) (*SessionStorage, error) {
	if redisConn.Client == nil {
		return nil, fmt.Errorf("redis client is nil")
	}

	return &SessionStorage{
		client:          redisConn.Client,
		sessionTTL:      redisConn.SessionTTL,
		revokedTokenTTL: redisConn.RevokedTokenTTL,
	}, nil
}

func (s *SessionStorage) CreateSession(ctx context.Context, session entity.Session) error {
	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key := s.sessionKey(session.RefreshToken)
	pipe := s.client.Pipeline()

	pipe.Set(ctx, key, sessionData, s.sessionTTL)

	refreshKey := s.refreshTokenKey(session.RefreshToken)
	pipe.HSet(ctx, refreshKey, map[string]interface{}{
		"user_id":    session.UserID,
		"app_id":     session.AppID,
		"device_id":  session.DeviceID,
		"expires_at": session.ExpiresAt.Unix(),
	})
	pipe.ExpireAt(ctx, refreshKey, session.ExpiresAt)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

func (s *SessionStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	key := s.sessionKey(refreshToken)
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return entity.Session{}, storage.ErrSessionNotFound
		}
		return entity.Session{}, fmt.Errorf("failed to get session: %w", err)
	}

	var session entity.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return entity.Session{}, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return session, nil
}

func (s *SessionStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	pipe := s.client.Pipeline()

	sessionKey := s.sessionKey(refreshToken)
	pipe.Del(ctx, sessionKey)

	refreshKey := s.refreshTokenKey(refreshToken)
	pipe.Del(ctx, refreshKey)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func (s *SessionStorage) DeleteSession(ctx context.Context, session entity.Session) error {
	pattern := fmt.Sprintf("%s*", refreshTokenKeyPrefix)
	iter := s.client.Scan(ctx, 0, pattern, 0).Iterator()

	for iter.Next(ctx) {
		key := iter.Val()
		data, err := s.client.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}

		if data["user_id"] == session.UserID &&
			data["app_id"] == session.AppID &&
			data["device_id"] == session.DeviceID {
			refreshToken := key[len(refreshTokenKeyPrefix):]
			return s.DeleteRefreshToken(ctx, refreshToken)
		}
	}

	return storage.ErrSessionNotFound
}

func (s *SessionStorage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	pattern := fmt.Sprintf("%s*", refreshTokenKeyPrefix)
	return s.deleteSessionsByPattern(ctx, pattern, func(data map[string]string) bool {
		return data["user_id"] == userID && data["app_id"] == appID
	})
}

func (s *SessionStorage) DeleteAllUserDevices(ctx context.Context, userID, appID string) error {
	return fmt.Errorf("device operations are not supported in redis storage")
}

func (s *SessionStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	return "", storage.ErrUserDeviceNotFound
}

func (s *SessionStorage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	return fmt.Errorf("device operations are not supported in redis storage")
}

func (s *SessionStorage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	return fmt.Errorf("device operations are not supported in redis storage")
}

func (s *SessionStorage) deleteSessionsByPattern(ctx context.Context, pattern string, filter func(map[string]string) bool) error {
	iter := s.client.Scan(ctx, 0, pattern, 0).Iterator()

	for iter.Next(ctx) {
		key := iter.Val()
		data, err := s.client.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}

		if filter(data) {
			refreshToken := key[len(refreshTokenKeyPrefix):]
			if err := s.DeleteRefreshToken(ctx, refreshToken); err != nil {
				return fmt.Errorf("failed to delete session: %w", err)
			}
		}
	}

	return nil
}

func (s *SessionStorage) sessionKey(refreshToken string) string {
	return fmt.Sprintf("%s%s", sessionKeyPrefix, refreshToken)
}

func (s *SessionStorage) refreshTokenKey(refreshToken string) string {
	return fmt.Sprintf("%s%s", refreshTokenKeyPrefix, refreshToken)
}

func (s *SessionStorage) RevokeAccessToken(ctx context.Context, token string) error {
	key := s.revokedTokenKey(token)
	if err := s.client.Set(ctx, key, "revoked", s.revokedTokenTTL).Err(); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}
	return nil
}

func (s *SessionStorage) IsAccessTokenRevoked(ctx context.Context, token string) (bool, error) {
	key := s.revokedTokenKey(token)
	_, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check if access token is revoked: %w", err)
	}
	return true, nil
}

func (s *SessionStorage) revokedTokenKey(token string) string {
	return fmt.Sprintf("%s%s", revokedTokenKeyPrefix, token)
}
