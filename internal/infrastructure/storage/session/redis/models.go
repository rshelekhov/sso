package redis

import (
	"strconv"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

const (
	deviceKeyPrefix       = "device"
	sessionKeyPrefix      = "session"
	revokedTokenKeyPrefix = "revoked_token"
	refreshIndexPrefix    = "refresh_index"
	userIDKeyPrefix       = "user_id"
	deviceIDKeyPrefix     = "device_id"
	expiresAtKeyPrefix    = "expires_at"
	refreshTokenKeyPrefix = "refresh_token"
)

func toRedisSessionData(session entity.Session) map[string]any {
	return map[string]any{
		userIDKeyPrefix:       session.UserID,
		deviceIDKeyPrefix:     session.DeviceID,
		refreshTokenKeyPrefix: session.RefreshToken,
		expiresAtKeyPrefix:    session.ExpiresAt.Unix(),
	}
}

func toSessionEntity(data map[string]string) entity.Session {
	expiresAt, _ := strconv.ParseInt(data[expiresAtKeyPrefix], 10, 64)
	return entity.Session{
		UserID:       data[userIDKeyPrefix],
		DeviceID:     data[deviceIDKeyPrefix],
		RefreshToken: data[refreshTokenKeyPrefix],
		ExpiresAt:    time.Unix(expiresAt, 0),
	}
}
