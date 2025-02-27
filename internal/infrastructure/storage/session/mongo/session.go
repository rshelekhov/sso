package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SessionStorage struct {
	sessionsColl *mongo.Collection
	devicesColl  *mongo.Collection
	timeout      time.Duration
}

const (
	sessionsCollectionName = "sessions"
	devicesCollectionName  = "user_devices"
)

func NewSessionStorage(db *mongo.Database, timeout time.Duration) (*SessionStorage, error) {
	const op = "storage.session.mongo.NewSessionStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	sessionsColl := db.Collection(sessionsCollectionName)
	devicesColl := db.Collection(devicesCollectionName)

	return &SessionStorage{
		sessionsColl: sessionsColl,
		devicesColl:  devicesColl,
		timeout:      timeout,
	}, nil
}

func (s *SessionStorage) CreateSession(ctx context.Context, session entity.Session) error {
	const method = "storage.session.mongo.CreateSession"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	doc := toSessionDoc(session)

	if _, err := s.sessionsColl.InsertOne(ctx, doc); err != nil {
		return fmt.Errorf("%s: failed to create user session: %w", method, err)
	}

	return nil
}

func (s *SessionStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	const method = "storage.session.mongo.GetSessionByRefreshToken"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{fieldRefreshToken: refreshToken}

	result := s.sessionsColl.FindOne(ctx, filter)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return entity.Session{}, storage.ErrSessionNotFound
		}
		return entity.Session{}, fmt.Errorf("%s: failed to get session: %w", method, err)
	}

	var sessionDoc sessionDocument
	if err := result.Decode(&sessionDoc); err != nil {
		return entity.Session{}, fmt.Errorf("%s: failed to decode session: %w", method, err)
	}

	return toSessionEntity(sessionDoc), nil
}

func (s *SessionStorage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	const method = "storage.session.mongo.UpdateLastVisitedAt"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldID: session.DeviceID,
	}

	update := bson.M{
		"$set": bson.M{fieldLastVisitedAt: session.LastVisitedAt},
	}

	result := s.devicesColl.FindOneAndUpdate(ctx, filter, update)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return storage.ErrSessionNotFound
		}
		return fmt.Errorf("%s: failed to update last visited at: %w", method, err)
	}
	return nil
}

func (s *SessionStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	const method = "storage.session.mongo.DeleteRefreshToken"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{fieldRefreshToken: refreshToken}

	if _, err := s.sessionsColl.DeleteOne(ctx, filter); err != nil {
		return fmt.Errorf("%s: failed to delete refresh jwtoken: %w", method, err)
	}
	return nil
}

func (s *SessionStorage) DeleteSession(ctx context.Context, session entity.Session) error {
	const method = "storage.session.mongo.DeleteSession"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldUserID:   session.UserID,
		fieldAppID:    session.AppID,
		fieldDeviceID: session.DeviceID,
	}

	result, err := s.sessionsColl.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("%s: failed to delete session: %w", method, err)
	}

	if result.DeletedCount == 0 {
		return storage.ErrSessionNotFound
	}

	return nil
}

func (s *SessionStorage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	const method = "storage.session.mongo.DeleteAllSessions"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldUserID: userID,
		fieldAppID:  appID,
	}

	if _, err := s.sessionsColl.DeleteMany(ctx, filter); err != nil {
		return fmt.Errorf("%s: failed to delete all sessions: %w", method, err)
	}
	return nil
}

func (s *SessionStorage) DeleteAllUserDevices(ctx context.Context, userID, appID string) error {
	const method = "storage.session.mongo.DeleteAllUserDevices"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldUserID: userID,
		fieldAppID:  appID,
	}

	if _, err := s.devicesColl.DeleteMany(ctx, filter); err != nil {
		return fmt.Errorf("%s: failed to delete all user devices: %w", method, err)
	}
	return nil
}

func (s *SessionStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	const method = "storage.session.mongo.GetUserDeviceID"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldUserID:    userID,
		fieldUserAgent: userAgent,
	}

	opts := options.FindOne().SetProjection(bson.M{fieldID: 1})

	var resultDoc struct {
		ID string `bson:"_id"`
	}

	result := s.devicesColl.FindOne(ctx, filter, opts)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", storage.ErrUserDeviceNotFound
		}
		return "", fmt.Errorf("%s: failed to get id of user device: %w", method, err)
	}

	if err := result.Decode(&resultDoc); err != nil {
		return "", fmt.Errorf("%s: failed to decode user device: %w", method, err)
	}

	return resultDoc.ID, nil
}

func (s *SessionStorage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	const method = "storage.session.mongo.RegisterDevice"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	doc := toDeviceDoc(device)

	if _, err := s.devicesColl.InsertOne(ctx, doc); err != nil {
		return fmt.Errorf("%s: failed to register user device: %w", method, err)
	}
	return nil
}
