package mongo

import (
	"context"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserStorage struct {
	client *mongo.Client
	dbName string
}

func NewUserStorage(client *mongo.Client, dbName string) *UserStorage {
	return &UserStorage{
		client: client,
		dbName: dbName,
	}
}

func (s *UserStorage) GetUserByID(ctx context.Context, appID, userID string) (entity.User, error) {
	// TODO: implement
	return entity.User{}, nil
}

func (s *UserStorage) GetUserByEmail(ctx context.Context, appID, email string) (entity.User, error) {
	// TODO: implement
	return entity.User{}, nil
}

func (s *UserStorage) GetUserData(ctx context.Context, appID, userID string) (entity.User, error) {
	// TODO: implement
	return entity.User{}, nil
}

func (s *UserStorage) UpdateUser(ctx context.Context, user entity.User) error {
	// TODO: implement
	return nil
}

func (s *UserStorage) DeleteUser(ctx context.Context, user entity.User) error {
	// TODO: implement
	return nil
}

func (s *UserStorage) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	// TODO: implement
	return "", nil
}

func (s *UserStorage) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	// TODO: implement
	return "", nil
}

func (s *UserStorage) DeleteAllTokens(ctx context.Context, appID, userID string) error {
	// TODO: implement
	return nil
}
