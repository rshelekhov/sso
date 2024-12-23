package postgres

import "github.com/rshelekhov/sso/src/infrastructure/storage/app/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
