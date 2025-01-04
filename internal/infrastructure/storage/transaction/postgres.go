package transaction

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresMgr struct {
	pool *pgxpool.Pool
}

type txKey struct{}

var ErrTransactionNotFoundInCtx = fmt.Errorf("transaction not found in context")

func (tm *PostgresMgr) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	tx, err := tm.pool.Begin(ctx)
	if err != nil {
		return err
	}

	txCtx := context.WithValue(ctx, txKey{}, tx)

	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil {
				err = fmt.Errorf("tx err: %v, rb err: %v", err, rbErr)
			}
		} else {
			err = tx.Commit(ctx)
		}
	}()

	err = fn(txCtx)

	return err
}

func (tm *PostgresMgr) ExecWithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	if !ok {
		return ErrTransactionNotFoundInCtx
	}

	return fn(tx)
}
