package usecase

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"log/slog"
	"time"

	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

type (
	AppUsecase interface {
		RegisterApp(ctx context.Context, appName string) error
		DeleteApp(ctx context.Context, appID, secretHash string) error
	}

	KeyManager interface {
		GenerateAndSavePrivateKey(appID string) error
		PublicKey(appID string) (interface{}, error)
	}

	AppStorage interface {
		RegisterApp(ctx context.Context, data entity.AppData) error
		DeleteApp(ctx context.Context, data entity.AppData) error
	}
)

type appUsecase struct {
	log        *slog.Logger
	keyManager KeyManager
	storage    AppStorage
}

func NewAppUsecase(
	log *slog.Logger,
	km KeyManager,
	storage AppStorage,
) AppUsecase {
	return &appUsecase{
		log:        log,
		keyManager: km,
		storage:    storage,
	}
}

func (u *appUsecase) RegisterApp(ctx context.Context, appName string) error {
	const method = "usecase.appUsecase.RegisterApp"

	log := u.log.With(slog.String("method", method))

	appID := ksuid.New().String()

	secretHash, err := u.generateAndHashSecret(appName)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToGenerateSecretHash.Error(),
			slog.Any("error", err),
		)
		return err
	}

	currentTime := time.Now()

	appData := entity.AppData{
		ID:        appID,
		Name:      appName,
		Secret:    secretHash,
		Status:    entity.AppStatusActive,
		CreatedAt: currentTime,
		UpdatedAt: currentTime,
	}

	if err = u.storage.RegisterApp(ctx, appData); err != nil {
		if errors.Is(err, storage.ErrAppAlreadyExists) {
			log.LogAttrs(ctx, slog.LevelError, domain.ErrAppAlreadyExists.Error())
			return domain.ErrAppAlreadyExists
		}

		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToRegisterApp.Error(),
			slog.String("appID", appID),
			slog.Any("error", err),
		)

		return domain.ErrFailedToRegisterApp
	}

	if err = u.keyManager.GenerateAndSavePrivateKey(appID); err != nil {
		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToGenerateAndSavePrivateKey.Error(),
			slog.String("appID", appID),
			slog.Any("error", err),
		)

		// Rollback
		err = u.DeleteApp(ctx, appData.ID, appData.Secret)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToDeleteApp.Error(),
				slog.String("appID", appID),
				slog.Any("error", err),
			)
			return domain.ErrFailedToDeleteApp
		}

		return domain.ErrFailedToGenerateAndSavePrivateKey
	}

	log.LogAttrs(ctx, slog.LevelInfo, "App registered successfully",
		slog.String("appName", appName),
		slog.String("appID", appID),
	)

	return nil
}

func (u *appUsecase) DeleteApp(ctx context.Context, appID, secretHash string) error {
	const method = "usecase.appUsecase.RegisterApp"

	log := u.log.With(slog.String("method", method))

	appData := entity.AppData{
		ID:        appID,
		Secret:    secretHash,
		DeletedAt: time.Now(),
	}

	if err := u.storage.DeleteApp(ctx, appData); err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.LogAttrs(ctx, slog.LevelError, domain.ErrAppNotFound.Error())
			return domain.ErrAppNotFound
		}

		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToDeleteApp.Error(),
			slog.String("appID", appID),
			slog.Any("error", err),
		)

		return domain.ErrFailedToDeleteApp
	}

	log.Info("app deleted", slog.String("appID", appID))

	return nil
}

func (u *appUsecase) generateAndHashSecret(name string) (string, error) {
	const method = "usecase.appUsecase.generateAndHashSecret"

	if name == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrAppNameIsEmpty)
	}

	secret := fmt.Sprintf("%s_%s", name, ksuid.New().String())

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	secretHmac := hmac.New(sha256.New, salt)
	_, err := secretHmac.Write([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}

	secretHashBcrypt, err := bcrypt.GenerateFromPassword(secretHmac.Sum(nil), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}

	return string(secretHashBcrypt), nil
}
