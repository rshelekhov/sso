package transaction

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoMgr struct {
	client *mongo.Client
}

func (tm *MongoMgr) WithinTransaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	session, err := tm.client.StartSession()
	if err != nil {
		return fmt.Errorf("failed to start session: %w", err)
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		return nil, fn(sessCtx)
	})

	return err
}
