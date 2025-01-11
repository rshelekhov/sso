package mongo

import (
	"context"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type AuthStorage struct {
	client *mongo.Client
	dbName string
}

func NewAuthStorage(client *mongo.Client, dbName string) *AuthStorage {
	return &AuthStorage{
		client: client,
		dbName: dbName,
	}
}

func (s *AuthStorage) ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error {
	// TODO: implement
	return nil
}

func (s *AuthStorage) RegisterUser(ctx context.Context, user entity.User) error {
	// TODO: implement
	return nil
}

func (s *AuthStorage) MarkEmailVerified(ctx context.Context, userID, appID string) error {
	// TODO: implement
	return nil
}
