package suite

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rshelekhov/golib/config"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	clientv1 "github.com/rshelekhov/sso-protos/gen/go/api/client/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	testStorage "github.com/rshelekhov/sso/api_tests/suite/storage"
	appConfig "github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Suite struct {
	*testing.T
	Cfg                     *appConfig.ServerSettings
	AuthService             authv1.AuthServiceClient
	UserService             userv1.UserServiceClient
	ClientManagementService clientv1.ClientManagementServiceClient
	Storage                 testStorage.TestStorage
}

const (
	//nolint:staticcheck
	CONFIG_PATH       = "CONFIG_PATH"
	defaultConfigPath = "../config/config.yaml"
	grpcHost          = "localhost"
)

// New creates new test suite
func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoad[appConfig.ServerSettings](
		config.WithSkipFlags(true),
		config.WithFiles([]string{configPath()}),
	)

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
		T:                       t,
		Cfg:                     cfg,
		AuthService:             authv1.NewAuthServiceClient(cc),
		UserService:             userv1.NewUserServiceClient(cc),
		ClientManagementService: clientv1.NewClientManagementServiceClient(cc),
		Storage:                 testStorage,
	}
}

func configPath() string {
	if v := os.Getenv(CONFIG_PATH); v != "" {
		return v
	}

	return defaultConfigPath
}

func grpcAddress(cfg *appConfig.ServerSettings) string {
	return net.JoinHostPort(grpcHost, cfg.GRPCServer.Port)
}

func newDBConnection(cfg settings.Storage) (*storage.DBConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbConnection, err := storage.NewDBConnection(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return dbConnection, nil
}
