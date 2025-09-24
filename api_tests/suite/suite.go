package suite

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cristalhq/aconfig"
	"github.com/cristalhq/aconfig/aconfigdotenv"
	"github.com/cristalhq/aconfig/aconfigyaml"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	clientv1 "github.com/rshelekhov/sso-protos/gen/go/api/client/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	testStorage "github.com/rshelekhov/sso/api_tests/suite/storage"
	appConfig "github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/observability/metrics"
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
)

// New creates new test suite
func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := mustLoadConfig(configPath())

	// Use longer timeout for tests to handle heavy operations like Argon2 hashing
	testTimeout := 60 * time.Second
	ctx, cancelCtx := context.WithTimeout(context.Background(), testTimeout)

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

// mustLoadConfig loads config directly from file path, avoiding environment variable race conditions
func mustLoadConfig(configPath string) *appConfig.ServerSettings {
	cfg := &appConfig.ServerSettings{}

	loader := aconfig.LoaderFor(cfg, aconfig.Config{
		Files:              []string{configPath},
		AllowUnknownFields: true,
		SkipFlags:          true,
		FileDecoders: map[string]aconfig.FileDecoder{
			".yaml": aconfigyaml.New(),
			".yml":  aconfigyaml.New(),
			".env":  aconfigdotenv.New(),
		},
	})

	err := loader.Load()
	if err != nil {
		panic(fmt.Sprintf("error loading config file %s: %s", configPath, err))
	}

	return cfg
}

func configPath() string {
	configFile := "config/config.test.yaml"

	if v := os.Getenv(CONFIG_PATH); v != "" {
		configFile = v
	}

	// Try direct path first
	if _, err := os.Stat(configFile); err == nil {
		return configFile
	}

	// If not found, try relative to parent directory (when running from api_tests)
	parentPath := "../" + configFile
	if _, err := os.Stat(parentPath); err == nil {
		return parentPath
	}

	// Fallback to default
	return defaultConfigPath
}

func grpcAddress(cfg *appConfig.ServerSettings) string {
	host := os.Getenv("SSO_HOST")
	if host == "" {
		host = cfg.GRPCServer.Host + ":" + cfg.GRPCServer.Port
	}
	return host
}

func newDBConnection(cfg settings.Storage) (*storage.DBConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use no-op recorder for tests to avoid metrics overhead
	recorder := &metrics.NoOpRecorder{}
	dbConnection, err := storage.NewDBConnection(ctx, cfg, recorder)
	if err != nil {
		return nil, err
	}

	return dbConnection, nil
}
