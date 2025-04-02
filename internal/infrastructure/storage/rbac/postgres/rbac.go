package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/rbac/postgres/sqlc"
)

type RBACStorage struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

func NewRBACStorage(pool *pgxpool.Pool) *RBACStorage {
	return &RBACStorage{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (s *RBACStorage) GetUserRole(ctx context.Context, appID, userID string) (string, error) {
	const method = "storage.user.postgres.GetUserRole"

	role, err := s.queries.GetUserRole(ctx, sqlc.GetUserRoleParams{
		ID:    userID,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to get user role: %w", method, err)
	}

	return role, nil
}

func (s *RBACStorage) SetUserRole(ctx context.Context, appID, userID, role string) error {
	const method = "storage.user.postgres.SetUserRole"

	_, err := s.queries.SetUserRole(ctx, sqlc.SetUserRoleParams{
		ID:    userID,
		AppID: appID,
		Role:  role,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to set user role: %w", method, err)
	}

	return nil
}
