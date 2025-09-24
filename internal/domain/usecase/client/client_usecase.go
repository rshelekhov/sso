package client

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"go.opentelemetry.io/otel/attribute"

	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	log     *slog.Logger
	keyMgr  KeyManager
	storage Storage
	metrics MetricsRecorder
}

type (
	KeyManager interface {
		GenerateAndSavePrivateKey(clientID string) error
		PublicKey(clientID string) (interface{}, error)
	}

	Storage interface {
		RegisterClient(ctx context.Context, data entity.ClientData) error
		DeleteClient(ctx context.Context, data entity.ClientData) error
	}
)

func NewUsecase(
	log *slog.Logger,
	km KeyManager,
	storage Storage,
	metrics MetricsRecorder,
) *Client {
	return &Client{
		log:     log,
		keyMgr:  km,
		storage: storage,
		metrics: metrics,
	}
}

func (u *Client) RegisterClient(ctx context.Context, clientName string) error {
	const method = "usecase.Client.RegisterClient"

	log := u.log.With(slog.String("method", method))

	u.metrics.RecordClientRegistrationsAttempt(ctx)

	clientID := ksuid.New().String()

	secretHash, err := u.generateAndHashSecret(clientName)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToGenerateSecretHash.Error(),
			slog.Any("error", err),
		)
		u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToGenerateSecretHash.Error()))
		return err
	}

	currentTime := time.Now()

	clientData := entity.ClientData{
		ID:        clientID,
		Name:      clientName,
		Secret:    secretHash,
		Status:    entity.ClientStatusActive,
		CreatedAt: currentTime,
		UpdatedAt: currentTime,
	}

	if err = u.storage.RegisterClient(ctx, clientData); err != nil {
		if errors.Is(err, storage.ErrClientAlreadyExists) {
			log.LogAttrs(ctx, slog.LevelError, domain.ErrClientAlreadyExists.Error())
			u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrClientAlreadyExists.Error()))
			return domain.ErrClientAlreadyExists
		}

		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToRegisterClient.Error(),
			slog.String("clientID", clientID),
			slog.Any("error", err),
		)

		u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToRegisterClient.Error()))
		return domain.ErrFailedToRegisterClient
	}

	if err = u.keyMgr.GenerateAndSavePrivateKey(clientID); err != nil {
		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToGenerateAndSavePrivateKey.Error(),
			slog.String("clientID", clientID),
			slog.Any("error", err),
		)

		// Rollback
		err = u.DeleteClient(ctx, clientData.ID, clientData.Secret)
		if err != nil {
			log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToDeleteClient.Error(),
				slog.String("clientID", clientID),
				slog.Any("error", err),
			)
			u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToDeleteClient.Error()))
			return domain.ErrFailedToDeleteClient
		}

		u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToGenerateAndSavePrivateKey.Error()))
		return domain.ErrFailedToGenerateAndSavePrivateKey
	}

	log.LogAttrs(ctx, slog.LevelInfo, "Client registered successfully",
		slog.String("clientName", clientName),
		slog.String("clientID", clientID),
	)

	u.metrics.RecordClientRegistrationsSuccess(ctx)

	return nil
}

func (u *Client) DeleteClient(ctx context.Context, clientID, secretHash string) error {
	const method = "usecase.Client.DeleteClient"

	log := u.log.With(slog.String("method", method))

	u.metrics.RecordClientDeletionsAttempt(ctx)

	clientData := entity.ClientData{
		ID:        clientID,
		Secret:    secretHash,
		DeletedAt: time.Now(),
	}

	if err := u.storage.DeleteClient(ctx, clientData); err != nil {
		if errors.Is(err, storage.ErrClientNotFound) {
			log.LogAttrs(ctx, slog.LevelError, domain.ErrClientNotFound.Error())
			u.metrics.RecordClientDeletionsError(ctx, attribute.String("error.type", domain.ErrClientNotFound.Error()))
			return domain.ErrClientNotFound
		}

		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToDeleteClient.Error(),
			slog.String("clientID", clientID),
			slog.Any("error", err),
		)

		u.metrics.RecordClientDeletionsError(ctx, attribute.String("error.type", domain.ErrFailedToDeleteClient.Error()))
		return domain.ErrFailedToDeleteClient
	}

	log.Info("client deleted", slog.String("clientID", clientID))

	u.metrics.RecordClientDeletionsSuccess(ctx)

	return nil
}

func (u *Client) generateAndHashSecret(name string) (string, error) {
	const method = "usecase.Client.generateAndHashSecret"

	if name == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrClientNameIsEmpty)
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
