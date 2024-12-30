package postgres

import "github.com/rshelekhov/sso/internal/infrastructure/storage/user/postgres/sqlc"

type Store interface {
	sqlc.Querier
}
