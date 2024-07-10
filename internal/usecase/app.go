package usecase

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type AppUsecase struct {
	log     *slog.Logger
	storage port.AppStorage
	cfg     *config.ServerSettings
}

func NewAppUsecase(log *slog.Logger, storage port.AppStorage, cfg *config.ServerSettings) *AppUsecase {
	return &AppUsecase{
		log:     log,
		storage: storage,
		cfg:     cfg,
	}
}

func (u *AppUsecase) RegisterApp(ctx context.Context, appName string) error {
	const method = "usecase.AppUsecase.RegisterApp"

	log := u.log.With(slog.String(key.Method, method))

	appID := ksuid.New().String()

	secretHash, err := u.generateAndHashSecret(appName)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, le.ErrFailedToGenerateSecretHash.Error(),
			slog.String(key.Error, err.Error()),
		)
		return le.ErrInternalServerError
	}

	currentTime := time.Now()

	appData := model.AppData{
		ID:        appID,
		Name:      appName,
		Secret:    secretHash,
		Status:    model.StatusActive,
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
			slog.String(key.Error, err.Error()),
		)
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

	salt := u.cfg.DefaultHashBcrypt.Salt
	if salt == "" {
		return "", fmt.Errorf("%s: salt is empty in the config file", method)
	}

	secretHmac := hmac.New(sha256.New, []byte(salt))
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
