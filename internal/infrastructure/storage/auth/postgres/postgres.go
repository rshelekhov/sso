package postgres

import "github.com/rshelekhov/sso/src/infrastructure/storage/auth/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
