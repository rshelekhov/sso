package mongo

import (
	"context"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type SessionStorage struct {
	client *mongo.Client
	dbName string
}

func NewSessionStorage(client *mongo.Client, dbName string) *SessionStorage {
	return &SessionStorage{
		client: client,
		dbName: dbName,
	}
}

func (s *SessionStorage) CreateSession(ctx context.Context, session entity.Session) error {
	// TODO: implement
	return nil
}

func (s *SessionStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	// TODO: implement
	return entity.Session{}, nil
}

func (s *SessionStorage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	// TODO: implement
	return nil
}

func (s *SessionStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	// TODO: implement
	return nil
}

func (s *SessionStorage) DeleteSession(ctx context.Context, session entity.Session) error {
	// TODO: implement
	return nil
}

func (s *SessionStorage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	// TODO: implement
	return nil
}

func (s *SessionStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	// TODO: implement
	return "", nil
}

func (s *SessionStorage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	// TODO: implement
	return nil
}
