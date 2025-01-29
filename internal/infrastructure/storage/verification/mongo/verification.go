package mongo

import (
	"context"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type VerificationStorage struct {
	client *mongo.Client
	dbName string
}

func NewVerificationStorage(client *mongo.Client, dbName string) *VerificationStorage {
	return &VerificationStorage{
		client: client,
		dbName: dbName,
	}
}

func (s *VerificationStorage) SaveVerificationToken(ctx context.Context, data entity.VerificationToken) error {
	// TODO: implement
	return nil
}

func (s *VerificationStorage) GetVerificationTokenData(ctx context.Context, token string) (entity.VerificationToken, error) {
	// TODO: implement
	return entity.VerificationToken{}, nil
}

func (s *VerificationStorage) DeleteVerificationToken(ctx context.Context, token string) error {
	// TODO: implement
	return nil
}
