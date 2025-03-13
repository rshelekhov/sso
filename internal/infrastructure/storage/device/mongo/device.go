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

type DeviceStorage struct {
	devicesColl *mongo.Collection
	timeout     time.Duration
}

const devicesCollectionName = "user_devices"

func NewDeviceStorage(db *mongo.Database, timeout time.Duration) (*DeviceStorage, error) {
	const op = "storage.session.mongo.NewSessionStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	devicesColl := db.Collection(devicesCollectionName)

	return &DeviceStorage{
		devicesColl: devicesColl,
		timeout:     timeout,
	}, nil
}

func (s *DeviceStorage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	const method = "storage.session.mongo.RegisterDevice"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	doc := toDeviceDoc(device)

	if _, err := s.devicesColl.InsertOne(ctx, doc); err != nil {
		return fmt.Errorf("%s: failed to register user device: %w", method, err)
	}
	return nil
}

func (s *DeviceStorage) GetUserDeviceID(ctx context.Context, userID, appID, userAgent string) (string, error) {
	const method = "storage.session.mongo.GetUserDeviceID"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldUserID:    userID,
		fieldAppID:     appID,
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

func (s *DeviceStorage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
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

func (s *DeviceStorage) DeleteAllUserDevices(ctx context.Context, userID, appID string) error {
	const method = "storage.session.mongo.DeleteAllUserDevices"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldUserID: userID,
		fieldAppID:  appID,
	}

	result, err := s.devicesColl.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("%s: failed to delete user devices: %w", method, err)
	}

	if result.DeletedCount == 0 {
		return storage.ErrUserDeviceNotFound
	}

	return nil
}
