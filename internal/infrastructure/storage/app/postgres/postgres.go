package postgres

import "github.com/rshelekhov/sso/internal/infrastructure/storage/app/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
