package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/rbac"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/auth"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/key"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
)

func main() {
	// Parse flags
	var (
		appID    string
		email    string
		password string
	)

	flag.StringVar(&appID, "app-id", "", "Application ID")
	flag.StringVar(&email, "email", "", "Admin email")
	flag.StringVar(&password, "password", "", "Admin password")
	flag.Parse()

	// Check required flags
	if appID == "" {
		log.Fatal("app-id is required")
	}
	if email == "" {
		log.Fatal("email is required")
	}
	if password == "" {
		log.Fatal("password is required")
	}

	// Initialize log
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Load config
	cfg := config.MustLoad()

	// Initialize context with cancellation
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Convert storage config
	storageConfig, err := settings.ToStorageConfig(cfg.Storage)
	if err != nil {
		log.Error("failed to convert storage config", "error", err)
		return
	}

	// Initialize DB connection
	dbConn, err := storage.NewDBConnection(storageConfig)
	if err != nil {
		log.Error("failed to init storage", "error", err)
		return
	}
	defer dbConn.Close()

	// Initialize transaction manager
	txMgr, err := transaction.NewManager(dbConn)
	if err != nil {
		log.Error("failed to init transaction manager", "error", err)
		return
	}

	// Initialize auth storage
	authStorage, err := auth.NewStorage(dbConn, txMgr)
	if err != nil {
		log.Error("failed to init auth storage", "error", err)
		return
	}

	// Initialize key storage for token manager
	keyStorageConfig, err := settings.ToKeyStorageConfig(cfg.KeyStorage)
	if err != nil {
		log.Error("failed to convert key storage config", "error", err)
		return
	}

	keyStorage, err := key.NewStorage(keyStorageConfig)
	if err != nil {
		log.Error("failed to init key storage", "error", err)
		return
	}

	// Initialize token manager
	jwtConfig, err := settings.ToJWTConfig(cfg.JWT)
	if err != nil {
		log.Error("failed to convert JWT config", "error", err)
		return
	}

	passwordHashConfig, err := settings.ToPasswordHashConfig(cfg.PasswordHash)
	if err != nil {
		log.Error("failed to convert password hash config", "error", err)
		return
	}

	tokenService := token.NewService(token.Config{
		JWT:                jwtConfig,
		PasswordHashParams: passwordHashConfig,
	}, keyStorage)

	// Hash the password
	hash, err := tokenService.HashPassword(password)
	if err != nil {
		log.Error("failed to hash password", "error", err)
		return
	}

	// Create admin user with hashed password
	user := entity.NewUser(appID, email, hash, rbac.RoleAdmin.String())
	user.Verified = true // Mark email as verified for admin

	// Register admin user within transaction
	err = txMgr.WithinTransaction(ctx, func(ctx context.Context) error {
		return authStorage.RegisterUser(ctx, user)
	})
	if err != nil {
		log.Error("failed to register admin user", "error", err)
		return
	}

	log.Info("admin user successfully registered",
		slog.String("email", email),
		slog.String("app_id", appID),
	)
}
