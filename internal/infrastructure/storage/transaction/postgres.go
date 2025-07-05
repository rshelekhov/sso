package transaction

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	postgresLib "github.com/rshelekhov/golib/db/postgres/pgxv5"
)

type PostgresMgr struct {
	txManager *postgresLib.TransactionManager
}

var ErrTransactionNotFoundInCtx = errors.New("transaction not found in context")

func (tm *PostgresMgr) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	return tm.txManager.RunReadCommitted(ctx, fn)
}

func (tm *PostgresMgr) ExecWithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	queryEngine := tm.txManager.GetQueryEngine(ctx)

	if tx, ok := queryEngine.(*postgresLib.Transaction); ok {
		return fn(tx.Tx)
	}

	return ErrTransactionNotFoundInCtx
}
