package redis

import (
	"strconv"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

const (
	clientIDKeyPrefix     = "client_id"
	sessionKeyPrefix      = "session"
	revokedTokenKeyPrefix = "revoked_token"
	refreshIndexPrefix    = "refresh_index"
	userIDKeyPrefix       = "user_id"
	deviceIDKeyPrefix     = "device_id"
	createdAtKeyPrefix    = "created_at"
	expiresAtKeyPrefix    = "expires_at"
	refreshTokenKeyPrefix = "refresh_token"
)

func toRedisSessionData(session entity.Session) map[string]any {
	return map[string]any{
		clientIDKeyPrefix:     session.ClientID,
		userIDKeyPrefix:       session.UserID,
		deviceIDKeyPrefix:     session.DeviceID,
		refreshTokenKeyPrefix: session.RefreshToken,
		createdAtKeyPrefix:    session.CreatedAt.Unix(),
		expiresAtKeyPrefix:    session.ExpiresAt.Unix(),
	}
}

func toSessionEntity(data map[string]string) entity.Session {
	createdAt, _ := strconv.ParseInt(data[createdAtKeyPrefix], 10, 64)
	expiresAt, _ := strconv.ParseInt(data[expiresAtKeyPrefix], 10, 64)
	return entity.Session{
		ClientID:     data[clientIDKeyPrefix],
		UserID:       data[userIDKeyPrefix],
		DeviceID:     data[deviceIDKeyPrefix],
		RefreshToken: data[refreshTokenKeyPrefix],
		CreatedAt:    time.Unix(createdAt, 0),
		ExpiresAt:    time.Unix(expiresAt, 0),
	}
}
