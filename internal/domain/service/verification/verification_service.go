package verification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/src/domain"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/infrastructure/storage"
	"time"
)

type Service struct {
	tokenExpiryTime time.Duration
	storage         Storage
}

type Storage interface {
	SaveVerificationToken(ctx context.Context, data entity.VerificationToken) error
	GetVerificationTokenData(ctx context.Context, token string) (entity.VerificationToken, error)
	DeleteVerificationToken(ctx context.Context, token string) error
}

func NewService(tokenExpiryTime time.Duration, storage Storage) *Service {
	return &Service{
		tokenExpiryTime: tokenExpiryTime,
		storage:         storage,
	}
}

func (s *Service) CreateToken(
	ctx context.Context,
	user entity.User,
	verificationEndpoint string,
	tokenType entity.VerificationTokenType,
) (
	entity.VerificationToken,
	error,
) {
	const method = "Service.verification.CreateToken"

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

func (s *Service) GetTokenData(ctx context.Context, token string) (entity.VerificationToken, error) {
	const method = "Service.verification.GetTokenData"

	tokenData, err := s.storage.GetVerificationTokenData(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrVerificationTokenNotFound) {
			return entity.VerificationToken{}, fmt.Errorf("%s: %w: %w", method, domain.ErrVerificationTokenNotFound, err)
		}

		return entity.VerificationToken{}, fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGetVerificationTokenData, err)
	}

	return tokenData, nil
}

func (s *Service) DeleteToken(ctx context.Context, token string) error {
	const method = "Service.verification.DeleteToken"

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
