package postgres

import "github.com/rshelekhov/sso/internal/infrastructure/storage/verification/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
