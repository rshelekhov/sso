package verification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"time"
)

type (
	Service interface {
		CreateToken(ctx context.Context, user entity.User, verificationEndpoint string, tokenType entity.VerificationTokenType) (entity.VerificationToken, error)
		GetTokenData(ctx context.Context, token string) (entity.VerificationToken, error)
		DeleteToken(ctx context.Context, token string) error
	}

	Storage interface {
		SaveVerificationToken(ctx context.Context, data entity.VerificationToken) error
		GetVerificationTokenData(ctx context.Context, token string) (entity.VerificationToken, error)
		DeleteVerificationToken(ctx context.Context, token string) error
	}
)

type service struct {
	tokenExpiryTime time.Duration
	storage         Storage
}

func NewService(tokenExpiryTime time.Duration, storage Storage) Service {
	return &service{
		tokenExpiryTime: tokenExpiryTime,
		storage:         storage,
	}
}

func (s *service) CreateToken(
	ctx context.Context,
	user entity.User,
	verificationEndpoint string,
	tokenType entity.VerificationTokenType,
) (
	entity.VerificationToken,
	error,
) {
	const method = "service.verification.CreateToken"

	verificationTokenString, err := generateToken()
	if err != nil {
		return entity.VerificationToken{}, fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGenerateVerificationToken, err)
	}

	tokenData := entity.NewVerificationToken(verificationTokenString, verificationEndpoint, user, tokenType, s.tokenExpiryTime)

	if err = s.storage.SaveVerificationToken(ctx, tokenData); err != nil {
		return entity.VerificationToken{}, fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToSaveVerificationToken, err)
	}

	return tokenData, nil
}

func (s *service) GetTokenData(ctx context.Context, token string) (entity.VerificationToken, error) {
	const method = "service.verification.GetTokenData"

	tokenData, err := s.storage.GetVerificationTokenData(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrVerificationTokenNotFound) {
			return entity.VerificationToken{}, fmt.Errorf("%s: %w: %w", method, domain.ErrVerificationTokenNotFound, err)
		}

		return entity.VerificationToken{}, fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGetVerificationTokenData, err)
	}

	return tokenData, nil
}

func (s *service) DeleteToken(ctx context.Context, token string) error {
	const method = "service.verification.DeleteToken"

	if err := s.storage.DeleteVerificationToken(ctx, token); err != nil {
		return fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToDeleteVerificationToken, err)
	}

	return nil
}

func generateToken() (string, error) {
	newToken := make([]byte, 32)
	_, err := rand.Read(newToken)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(newToken), nil
}
