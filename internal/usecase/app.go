package usecase

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

type AppUsecase struct {
	log     *slog.Logger
	storage port.AppStorage
	ts      jwtoken.TokenService
}

func NewAppUsecase(
	log *slog.Logger,
	storage port.AppStorage,
	ts jwtoken.TokenService,
) *AppUsecase {
	return &AppUsecase{
		log:     log,
		storage: storage,
		ts:      ts,
	}
}

func (u *AppUsecase) RegisterApp(ctx context.Context, appName string) error {
	const method = "usecase.AppUsecase.RegisterApp"

	log := u.log.With(slog.String(key.Method, method))

	appID := ksuid.New().String()

	secretHash, err := u.generateAndHashSecret(appName)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, le.ErrFailedToGenerateSecretHash.Error(),
			slog.Any(key.Error, err),
		)
		return le.ErrInternalServerError
	}

	currentTime := time.Now()

	appData := model.AppData{
		ID:        appID,
		Name:      appName,
		Secret:    secretHash,
		Status:    model.AppStatusActive,
		CreatedAt: currentTime,
		UpdatedAt: currentTime,
	}

	if err = u.storage.RegisterApp(ctx, appData); err != nil {
		if errors.Is(err, le.ErrAppAlreadyExists) {
			log.LogAttrs(ctx, slog.LevelError, le.ErrAppAlreadyExists.Error())
			return le.ErrAppAlreadyExists
		}

		log.LogAttrs(ctx, slog.LevelError, le.ErrInternalServerError.Error(),
			slog.String(key.AppID, appID),
			slog.Any(key.Error, err),
		)

		return le.ErrInternalServerError
	}

	if err = u.ts.GeneratePrivateKey(appID); err != nil {
		log.LogAttrs(ctx, slog.LevelError, le.ErrInternalServerError.Error(),
			slog.String(key.AppID, appID),
			slog.Any(key.Error, err),
		)

		err = u.DeleteApp(ctx, appData.ID, appData.Secret)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelError, le.ErrInternalServerError.Error(),
				slog.String(key.AppID, appID),
				slog.Any(key.Error, err),
			)
			return le.ErrInternalServerError
		}

		return le.ErrInternalServerError
	}

	log.LogAttrs(ctx, slog.LevelInfo, "App registered successfully",
		slog.String(key.AppName, appName),
		slog.String(key.AppID, appID),
		slog.String(key.SecretHash, secretHash),
	)

	return nil
}

func (u *AppUsecase) generateAndHashSecret(name string) (string, error) {
	const method = "usecase.AppUsecase.generateAndHashSecret"

	if name == "" {
		return "", fmt.Errorf("%s: name is empty", method)
	}

	secret := fmt.Sprintf("%s_%s", name, ksuid.New().String())

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	secretHmac := hmac.New(sha256.New, salt)
	_, err := secretHmac.Write([]byte(secret))
	if err != nil {
		return "", err
	}

	secretHashBcrypt, err := bcrypt.GenerateFromPassword(secretHmac.Sum(nil), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(secretHashBcrypt), nil
}

func (u *AppUsecase) DeleteApp(ctx context.Context, appID, secretHash string) error {
	const method = "usecase.AppUsecase.RegisterApp"

	log := u.log.With(slog.String(key.Method, method))

	appData := model.AppData{
		ID:        appID,
		Secret:    secretHash,
		DeletedAt: time.Now(),
	}

	if err := u.storage.DeleteApp(ctx, appData); err != nil {
		if errors.Is(err, le.ErrAppNotFound) {
			log.LogAttrs(ctx, slog.LevelError, le.ErrAppNotFound.Error())
			return le.ErrAppNotFound
		}

		log.LogAttrs(ctx, slog.LevelError, le.ErrInternalServerError.Error(),
			slog.String(key.AppID, appID),
			slog.Any(key.Error, err),
		)

		return le.ErrInternalServerError
	}

	log.Info("app deleted", slog.String(key.AppID, appID))

	return nil
}
