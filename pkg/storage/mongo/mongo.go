package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func New(cfg *Config) (*mongo.Client, error) {
	const method = "storage.mongo.New"

	clientOptions := options.Client().ApplyURI(cfg.URI)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to connect to mongodb: %w", method, err)
	}

	if err = client.Ping(context.Background(), nil); err != nil {
		return nil, fmt.Errorf("%s: failed to ping mongodb: %w", method, err)
	}

	return client, nil
}

type Config struct {
	URI    string
	DBName string
}
