package mongo

import (
	"context"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type AppStorage struct {
	client *mongo.Client
	dbName string
}

func NewAppStorage(client *mongo.Client, dbName string) *AppStorage {
	return &AppStorage{
		client: client,
		dbName: dbName,
	}
}

func (s *AppStorage) RegisterApp(ctx context.Context, data entity.AppData) error {
	// TODO: implement
	return nil
}

func (s *AppStorage) DeleteApp(ctx context.Context, data entity.AppData) error {
	// TODO: implement
	return nil
}

func (s *AppStorage) CheckAppIDExists(ctx context.Context, appID string) error {
	// TODO: implement
	return nil
}
