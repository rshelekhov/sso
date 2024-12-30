package postgres

import "github.com/rshelekhov/sso/internal/infrastructure/storage/session/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
