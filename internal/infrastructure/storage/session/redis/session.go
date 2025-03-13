package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
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

	storage := &SessionStorage{
		client:          redisConn.Client,
		sessionTTL:      redisConn.SessionTTL,
		revokedTokenTTL: redisConn.RevokedTokenTTL,
	}

	ctx := context.Background()
	if err := storage.client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	return storage, nil
}

func (s *SessionStorage) CreateSession(ctx context.Context, session entity.Session) error {
	const method = "storage.redis.CreateSession"

	sessionKey := s.sessionKey(session.UserID, session.AppID, session.DeviceID)
	data := toRedisSessionData(session)

	if err := s.client.HSet(ctx, sessionKey, data).Err(); err != nil {
		return fmt.Errorf("%s: failed to save session: %w", method, err)
	}

	refreshKey := s.refreshIndexKey(session.RefreshToken)
	if err := s.client.Set(ctx, refreshKey, sessionKey, 0).Err(); err != nil {
		return fmt.Errorf("%s: failed to save refresh token index: %w", method, err)
	}

	if err := s.client.ExpireAt(ctx, sessionKey, session.ExpiresAt).Err(); err != nil {
		return fmt.Errorf("%s: failed to set expiration for session: %w", method, err)
	}

	if err := s.client.ExpireAt(ctx, refreshKey, session.ExpiresAt).Err(); err != nil {
		return fmt.Errorf("%s: failed to set expiration for refresh token index: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	const method = "storage.redis.GetSessionByRefreshToken"

	refreshKey := s.refreshIndexKey(refreshToken)
	sessionKey, err := s.client.Get(ctx, refreshKey).Result()
	if err == redis.Nil {
		return entity.Session{}, storage.ErrSessionNotFound
	}
	if err != nil {
		return entity.Session{}, fmt.Errorf("%s: failed to get session key: %w", method, err)
	}

	data, err := s.client.HGetAll(ctx, sessionKey).Result()
	if err != nil {
		return entity.Session{}, fmt.Errorf("%s: failed to get session data: %w", method, err)
	}
	if len(data) == 0 {
		return entity.Session{}, storage.ErrSessionNotFound
	}

	return toSessionEntity(data), nil
}

func (s *SessionStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	const method = "storage.redis.DeleteRefreshToken"

	refreshKey := s.refreshIndexKey(refreshToken)
	sessionKey, err := s.client.Get(ctx, refreshKey).Result()
	if err == redis.Nil {
		return storage.ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("%s: failed to get session key: %w", method, err)
	}

	if err := s.client.Del(ctx, refreshKey, sessionKey).Err(); err != nil {
		return fmt.Errorf("%s: failed to delete session: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) DeleteSession(ctx context.Context, session entity.Session) error {
	const method = "storage.redis.DeleteSession"

	sessionKey := s.sessionKey(session.UserID, session.AppID, session.DeviceID)

	data, err := s.client.HGetAll(ctx, sessionKey).Result()
	if err != nil {
		return fmt.Errorf("%s: failed to get session data: %w", method, err)
	}
	if len(data) == 0 {
		return storage.ErrSessionNotFound
	}

	refreshKey := s.refreshIndexKey(data[refreshTokenKeyPrefix])

	if err := s.client.Del(ctx, sessionKey, refreshKey).Err(); err != nil {
		return fmt.Errorf("%s: failed to delete session: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	const method = "storage.redis.DeleteAllSessions"

	pattern := fmt.Sprintf("%s%s:%s:*", sessionKeyPrefix, userID, appID)
	iter := s.client.Scan(ctx, 0, pattern, 0).Iterator()

	var keysToDelete []string

	for iter.Next(ctx) {
		sessionKey := iter.Val()

		data, err := s.client.HGetAll(ctx, sessionKey).Result()
		if err != nil {
			return fmt.Errorf("%s: failed to get session data for key %s: %w", method, sessionKey, err)
		}
		if len(data) == 0 {
			// If there is no data, delete the "empty" key
			keysToDelete = append(keysToDelete, sessionKey)
			continue
		}

		refreshToken, ok := data[refreshTokenKeyPrefix]
		if !ok {
			// If there is no refresh token, this is incorrect data, delete such a session
			keysToDelete = append(keysToDelete, sessionKey)
			continue
		}

		keysToDelete = append(keysToDelete,
			sessionKey,
			s.refreshIndexKey(refreshToken),
		)
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("%s: failed to iterate over sessions: %w", method, err)
	}

	if len(keysToDelete) > 0 {
		if err := s.client.Del(ctx, keysToDelete...).Err(); err != nil {
			return fmt.Errorf("%s: failed to delete sessions: %w", method, err)
		}
	}

	return nil
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

func (s *SessionStorage) sessionKey(userID, appID, deviceID string) string {
	return fmt.Sprintf("%s%s:%s:%s", sessionKeyPrefix, userID, appID, deviceID)
}

func (s *SessionStorage) refreshIndexKey(refreshToken string) string {
	return fmt.Sprintf("%s%s", refreshIndexPrefix, refreshToken)
}

func (s *SessionStorage) revokedTokenKey(token string) string {
	return fmt.Sprintf("%s%s", revokedTokenKeyPrefix, token)
}
