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

	"github.com/rshelekhov/golib/observability/tracing"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/lib/e"
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
		PublicKey(clientID string) (any, error)
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

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	if clientName == "" {
		tracing.RecordError(span, domain.ErrClientNameIsEmpty)
		return domain.ErrClientNameIsEmpty
	}

	span.SetAttributes(
		tracing.String("client.name", clientName),
	)

	u.metrics.RecordClientRegistrationsAttempt(ctx)

	clientID := ksuid.New().String()

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.name", clientName),
		slog.String("client.id", clientID),
	)

	ctx, generateAndHashSecretSpan := tracing.StartSpan(ctx, "generate_and_hash_secret")
	secretHash, err := u.generateAndHashSecret(clientName)
	if err != nil {
    tracing.RecordError(generateAndHashSecretSpan, err)
		generateAndHashSecretSpan.End()
    
		e.LogError(ctx, log, domain.ErrFailedToGenerateSecretHash, err)
		u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToGenerateSecretHash.Error()))
		return domain.ErrFailedToGenerateSecretHash
	}

	generateAndHashSecretSpan.End()

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
      tracing.RecordError(span, err)
			e.LogError(ctx, log, domain.ErrClientAlreadyExists, err)
			u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrClientAlreadyExists.Error()))
			return domain.ErrClientAlreadyExists
		}

		tracing.RecordError(span, err)
		e.LogError(ctx, log, domain.ErrFailedToRegisterClient, err)
		u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToRegisterClient.Error()))
		return domain.ErrFailedToRegisterClient
	}

	ctx, generateAndSavePrivateKeySpan := tracing.StartSpan(ctx, "generate_and_save_private_key")
	if err = u.keyMgr.GenerateAndSavePrivateKey(clientID); err != nil {
		tracing.RecordError(generateAndSavePrivateKeySpan, err)
		generateAndSavePrivateKeySpan.End()

		e.LogError(ctx, log, domain.ErrFailedToGenerateAndSavePrivateKey, err)

		// Rollback
		span.AddEvent("Got error, rolling back client registration")
		err = u.DeleteClient(ctx, clientData.ID, clientData.Secret)
		if err != nil {
      tracing.RecordError(generateAndSavePrivateKeySpan, err)
			generateAndSavePrivateKeySpan.End()
      
			e.LogError(ctx, log, domain.ErrFailedToDeleteClient, err)
			u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToDeleteClient.Error()))
			return domain.ErrFailedToDeleteClient
		}

		u.metrics.RecordClientRegistrationsError(ctx, attribute.String("error.type", domain.ErrFailedToGenerateAndSavePrivateKey.Error()))
		return domain.ErrFailedToGenerateAndSavePrivateKey
	}

	generateAndSavePrivateKeySpan.End()

	log.Info("client registered successfully",
		slog.String("client.name", clientName),
		slog.String("client.id", clientID),
	)

	u.metrics.RecordClientRegistrationsSuccess(ctx)

	return nil
}

func (u *Client) DeleteClient(ctx context.Context, clientID, secretHash string) error {
	const method = "usecase.Client.DeleteClient"

	ctx, span := tracing.StartSpan(ctx, method)
	defer span.End()

	log := u.log.With(
		slog.String("method", method),
		slog.String("client.id", clientID),
	)

	u.metrics.RecordClientDeletionsAttempt(ctx)

	clientData := entity.ClientData{
		ID:        clientID,
		Secret:    secretHash,
		DeletedAt: time.Now(),
	}

	if err := u.storage.DeleteClient(ctx, clientData); err != nil {
		if errors.Is(err, storage.ErrClientNotFound) {
      tracing.RecordError(span, err)
			e.LogError(ctx, log, domain.ErrClientNotFound, err)
			u.metrics.RecordClientDeletionsError(ctx, attribute.String("error.type", domain.ErrClientNotFound.Error()))
			return domain.ErrClientNotFound
		}
    
		u.metrics.RecordClientDeletionsError(ctx, attribute.String("error.type", domain.ErrFailedToDeleteClient.Error()))
		return domain.ErrFailedToDeleteClient
	}

	log.Info("client deleted")

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
