package storage

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/rshelekhov/sso/internal/storage/postgres"
)

func NewAppStorage(storage settings.AppStorage) (port.AppStorage, error) {
	switch storage.Type {
	case settings.AppStorageTypePostgres:
		if storage.Postgres == nil {
			return nil, le.ErrPostgresAppStorageSettingsEmpty
		}
		return postgres.NewAppStorage(*storage.Postgres)
	case settings.AppStorageTypeMongo:
		if storage.Mongo == nil {
			return nil, le.ErrMongoAppStorageSettingsEmpty
		}
		return mongo.NewAppStorage(*storage.Mongo)
	default:
		return nil, fmt.Errorf("unknown app storage type: %s", storage.Type)
	}
}
