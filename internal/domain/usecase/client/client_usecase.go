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

	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	log     *slog.Logger
	keyMgr  KeyManager
	storage Storage
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
) *Client {
	return &Client{
		log:     log,
		keyMgr:  km,
		storage: storage,
	}
}

func (u *Client) RegisterClient(ctx context.Context, clientName string) error {
	const method = "usecase.Client.RegisterClient"

	log := u.log.With(slog.String("method", method))

	clientID := ksuid.New().String()

	secretHash, err := u.generateAndHashSecret(clientName)
	if err != nil {
		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToGenerateSecretHash.Error(),
			slog.Any("error", err),
		)
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
			return domain.ErrClientAlreadyExists
		}

		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToRegisterClient.Error(),
			slog.String("clientID", clientID),
			slog.Any("error", err),
		)

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
			return domain.ErrFailedToDeleteClient
		}

		return domain.ErrFailedToGenerateAndSavePrivateKey
	}

	log.LogAttrs(ctx, slog.LevelInfo, "Client registered successfully",
		slog.String("clientName", clientName),
		slog.String("clientID", clientID),
	)

	return nil
}

func (u *Client) DeleteClient(ctx context.Context, clientID, secretHash string) error {
	const method = "usecase.Client.DeleteClient"

	log := u.log.With(slog.String("method", method))

	clientData := entity.ClientData{
		ID:        clientID,
		Secret:    secretHash,
		DeletedAt: time.Now(),
	}

	if err := u.storage.DeleteClient(ctx, clientData); err != nil {
		if errors.Is(err, storage.ErrClientNotFound) {
			log.LogAttrs(ctx, slog.LevelError, domain.ErrClientNotFound.Error())
			return domain.ErrClientNotFound
		}

		log.LogAttrs(ctx, slog.LevelError, domain.ErrFailedToDeleteClient.Error(),
			slog.String("clientID", clientID),
			slog.Any("error", err),
		)

		return domain.ErrFailedToDeleteClient
	}

	log.Info("client deleted", slog.String("clientID", clientID))

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
