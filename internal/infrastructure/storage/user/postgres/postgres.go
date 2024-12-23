package postgres

import "github.com/rshelekhov/sso/src/infrastructure/storage/user/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
