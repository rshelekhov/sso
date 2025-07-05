package transaction

import (
	"context"
	"time"

	mongoLib "github.com/rshelekhov/golib/db/mongo"
)

type MongoMgr struct {
	txManager mongoLib.TransactionManager
	timeout   time.Duration
}

func (tm *MongoMgr) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, tm.timeout)
	defer cancel()

	return tm.txManager.RunTransaction(ctx, fn)
}
