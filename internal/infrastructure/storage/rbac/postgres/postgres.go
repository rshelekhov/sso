package postgres

import "github.com/rshelekhov/sso/internal/infrastructure/storage/rbac/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
