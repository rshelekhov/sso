package postgres

import "github.com/rshelekhov/sso/internal/infrastructure/storage/auth/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
