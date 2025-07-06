package transaction

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	mongoLib "github.com/rshelekhov/golib/db/mongo"
	postgresLib "github.com/rshelekhov/golib/db/postgres/pgxv5"
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
		txManager := mongoLib.NewTransactionManager(dbConn.Mongo.Connection)
		return &MongoMgr{
			txManager: txManager,
			timeout:   dbConn.Mongo.Timeout,
		}, nil
	case storage.TypePostgres:
		txManager := postgresLib.NewTransactionManager(dbConn.Postgres.Connection)
		return &PostgresMgr{
			txManager: txManager,
		}, nil
	default:
		return nil, fmt.Errorf("unknown storage type: %s", dbConn.Type)
	}
}
