package storage

import (
	"context"
	"fmt"
	"time"

	mongoLib "github.com/rshelekhov/golib/db/mongo"
	postgresLib "github.com/rshelekhov/golib/db/postgres/pgxv5"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/mongo/common"
	"github.com/rshelekhov/sso/internal/observability/metrics"
	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DBConnection struct {
	Type     Type
	Mongo    *Mongo
	Postgres *Postgres
	recorder metrics.MetricsRecorder
}

type Type string

const (
	TypeMongo    Type = "mongo"
	TypePostgres Type = "postgres"
)

func (t Type) String() string {
	return string(t)
}

type Mongo struct {
	*mongoLib.Connection
	Timeout time.Duration
}

type Postgres struct {
	*postgresLib.Connection
}

func NewDBConnection(ctx context.Context, cfg settings.Storage, recorder metrics.MetricsRecorder) (*DBConnection, error) {
	switch cfg.Type {
	case settings.StorageTypeMongo:
		return newMongoStorage(ctx, cfg.Mongo)
	case settings.StorageTypePostgres:
		return newPostgresStorage(ctx, cfg.Postgres, recorder)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Type)
	}
}

func newMongoStorage(ctx context.Context, cfg *settings.MongoParams) (*DBConnection, error) {
	const method = "storage.newMongoStorage"

	connection, err := mongoLib.NewConnection(ctx, cfg.URI, cfg.DBName)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new mongodb storage: %w", method, err)
	}

	conn, ok := connection.(*mongoLib.Connection)
	if !ok {
		return nil, fmt.Errorf("%s: expected *mongoLib.Connection, got %T", method, connection)
	}

	if err = initializeCollection(conn.Database()); err != nil {
		return nil, fmt.Errorf("%s: failed to initialize collections: %w", method, err)
	}

	dbConn := &DBConnection{
		Type: TypeMongo,
		Mongo: &Mongo{
			Connection: conn,
			Timeout:    cfg.Timeout,
		},
	}

	// MongoDB doesn't provide detailed connection pool statistics
	// Only PostgreSQL metrics will be collected

	return dbConn, nil
}

func newPostgresStorage(ctx context.Context, cfg *settings.PostgresParams, recorder metrics.MetricsRecorder) (*DBConnection, error) {
	const method = "storage.newPostgresStorage"

	conn, err := postgresLib.NewConnectionPool(ctx, cfg.ConnURL)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new postgres storage: %w", method, err)
	}

	dbConn := &DBConnection{
		Type: TypePostgres,
		Postgres: &Postgres{
			Connection: conn,
		},
		recorder: recorder,
	}

	// Start collecting connection pool metrics
	go dbConn.collectPostgresMetrics(ctx)

	return dbConn, nil
}

func initializeCollection(db *mongo.Database) error {
	if err := createUserIndexes(db); err != nil {
		return err
	}
	return nil
}

func createUserIndexes(db *mongo.Database) error {
	coll := db.Collection(common.UsersCollectionName)

	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: common.FieldClientID, Value: 1},
				{Key: common.FieldID, Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			// Email should be unique for active (not soft-deleted) users
			Keys: bson.D{
				{Key: common.FieldClientID, Value: 1},
				{Key: common.FieldEmail, Value: 1},
			},
			Options: options.Index().
				SetUnique(true).
				SetPartialFilterExpression(bson.D{
					{
						Key:   common.FieldDeletedAt,
						Value: bson.D{{Key: "$eq", Value: nil}},
					},
				}),
		},
	}

	_, err := coll.Indexes().CreateMany(context.Background(), indexes)
	if err != nil {
		return fmt.Errorf("failed to create user indexes: %w", err)
	}

	return nil
}

func (d *DBConnection) collectPostgresMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Collect metrics every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.Postgres != nil && d.Postgres.Pool() != nil {
				pool := d.Postgres.Pool()
				poolStats := pool.Stat()
				config := pool.Config()

				stats := infrastructure.PostgresConnectionPoolStats{
					Acquired:        int64(poolStats.AcquiredConns()),
					Idle:            int64(poolStats.IdleConns()),
					Total:           int64(poolStats.TotalConns()),
					Max:             int64(config.MaxConns),
					Min:             int64(config.MinConns),
					AcquireCount:    poolStats.AcquireCount(),
					AcquireDuration: poolStats.AcquireDuration(),
					Constructing:    int64(poolStats.ConstructingConns()),
				}
				d.recorder.RecordDBConnectionPoolStats("postgresql", stats)
			}
		}
	}
}

func (d *DBConnection) Close(ctx context.Context) error {
	const method = "storage.DBConnection.Close"

	switch d.Type {
	case TypeMongo:
		return d.Mongo.Close(ctx)
	case TypePostgres:
		d.Postgres.Close()
		return nil
	default:
		return fmt.Errorf("%s: unknown storage type: %s", method, d.Type)
	}
}
