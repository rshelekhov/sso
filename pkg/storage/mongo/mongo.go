package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func New(cfg *Config) (*mongo.Client, error) {
	const method = "storage.mongo.New"

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(cfg.URI).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to connect to mongodb: %w", method, err)
	}

	if err = client.Ping(context.Background(), nil); err != nil {
		return nil, fmt.Errorf("%s: failed to ping mongodb: %w", method, err)
	}

	return client, nil
}

func Close(client *mongo.Client) error {
	return client.Disconnect(context.Background())
}

type Config struct {
	URI    string
	DBName string
}
