package postgres

import "github.com/rshelekhov/sso/internal/infrastructure/storage/client/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
