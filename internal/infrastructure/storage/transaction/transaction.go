package transaction

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type Manager interface {
	WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type PostgresManager interface {
	WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) error
	ExecWithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error
}

func NewManager(dbConn *storage.DBConnection) (Manager, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return &MongoMgr{
			client:  dbConn.Mongo.Client,
			timeout: dbConn.Mongo.Timeout,
		}, nil
	case storage.TypePostgres:
		return &PostgresMgr{
			pool: dbConn.Postgres.Pool,
		}, nil
	default:
		return nil, fmt.Errorf("unknown storage type: %s", dbConn.Type)
	}
}
