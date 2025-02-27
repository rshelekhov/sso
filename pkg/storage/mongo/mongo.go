package mongo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DB struct {
	Database *mongo.Database
	Client   *mongo.Client
	Timeout  time.Duration
}

func New(cfg *Config) (DB, error) {
	const method = "storage.mongo.New"

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().
		ApplyURI(cfg.URI).
		SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(context.Background(), opts)
	if err != nil {
		return DB{}, fmt.Errorf("%s: failed to connect to mongodb: %w", method, err)
	}

	if err = client.Ping(context.Background(), nil); err != nil {
		return DB{}, fmt.Errorf("%s: failed to ping mongodb: %w", method, err)
	}

	database := client.Database(cfg.DBName)

	return DB{
		Database: database,
		Client:   client,
		Timeout:  cfg.Timeout,
	}, nil
}

func Close(client *mongo.Client) error {
	return client.Disconnect(context.Background())
}

type Config struct {
	URI     string
	DBName  string
	Timeout time.Duration
}
