package postgres

import "github.com/rshelekhov/sso/src/infrastructure/storage/session/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
