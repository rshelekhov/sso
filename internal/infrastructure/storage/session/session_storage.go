package session

import (
	"errors"

	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	redisStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/session/redis"
)

var (
	ErrMongoSessionStorageSettingsEmpty    = errors.New("mongo session storage settings are empty")
	ErrPostgresSessionStorageSettingsEmpty = errors.New("postgres session storage settings are empty")
)

func NewStorage(redisConn *storage.RedisConnection) (session.SessionStorage, error) {
	storage, err := redisStorage.NewSessionStorage(redisConn)
	if err != nil {
		return nil, err
	}

	return storage, nil
}
