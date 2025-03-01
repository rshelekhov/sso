package suite

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	testStorage "github.com/rshelekhov/sso/api_tests/suite/storage"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Suite struct {
	*testing.T
	Cfg        *config.ServerSettings
	AuthClient ssov1.AuthClient
	Storage    testStorage.TestStorage
}

const (
	//nolint:revive
	CONFIG_PATH       = "CONFIG_PATH"
	defaultConfigPath = "../config/.env"
	grpcHost          = "localhost"
)

// New creates new test suite
func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoadPath(configPath())

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPCServer.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
	})

	cc, err := grpc.NewClient(grpcAddress(cfg), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal("grpc server connection failed: ", err)
	}

	dbConn, err := newDBConnection(cfg.Storage)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to init database connection for the test suite: %w", err))
	}

	testStorage, err := testStorage.New(dbConn)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to init test storage for the test suite: %w", err))
	}

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: ssov1.NewAuthClient(cc),
		Storage:    testStorage,
	}
}

func configPath() string {
	if v := os.Getenv(CONFIG_PATH); v != "" {
		return v
	}

	return defaultConfigPath
}

func grpcAddress(cfg *config.ServerSettings) string {
	return net.JoinHostPort(grpcHost, cfg.GRPCServer.Port)
}

func newDBConnection(cfg settings.Storage) (*storage.DBConnection, error) {
	storageConfig, err := settings.ToStorageConfig(cfg)
	if err != nil {
		return nil, err
	}

	dbConnection, err := storage.NewDBConnection(storageConfig)
	if err != nil {
		return nil, err
	}

	return dbConnection, nil
}
