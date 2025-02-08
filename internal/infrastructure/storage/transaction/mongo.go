package transaction

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type MongoMgr struct {
	client  *mongo.Client
	timeout time.Duration
}

func (tm *MongoMgr) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, tm.timeout)
	defer cancel()

	session, err := tm.client.StartSession()
	if err != nil {
		return fmt.Errorf("failed to start session: %w", err)
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		if err := fn(sessCtx); err != nil {
			return nil, fmt.Errorf("transaction execution failed: %w", err)
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("tx err: %w", err)
	}

	return err
}
