package postgres

import "github.com/rshelekhov/sso/src/infrastructure/storage/verification/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
