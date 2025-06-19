package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/client/postgres/sqlc"
)

type ClientStorage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewClientStorage(pool *pgxpool.Pool) *ClientStorage {
	queries := sqlc.New(pool)

	return &ClientStorage{
		Pool:    pool,
		Queries: queries,
	}
}

const UniqueViolationErrorCode = "23505"

func (s *ClientStorage) RegisterClient(ctx context.Context, data entity.ClientData) error {
	const method = "storage.client.postgres.RegisterClient"

	if err := s.InsertClient(ctx, sqlc.InsertClientParams{
		ID:        data.ID,
		Name:      data.Name,
		Secret:    data.Secret,
		Status:    int32(data.Status),
		CreatedAt: data.CreatedAt,
		UpdatedAt: data.UpdatedAt,
	}); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == UniqueViolationErrorCode {
			return storage.ErrClientAlreadyExists
		}
		return fmt.Errorf("%s: failed to register client: %w", method, err)
	}
	return nil
}

func (s *ClientStorage) DeleteClient(ctx context.Context, data entity.ClientData) error {
	const method = "storage.client.postgres.DeleteClient"

	if err := s.Queries.DeleteClient(ctx, sqlc.DeleteClientParams{
		ID:     data.ID,
		Secret: data.Secret,
		DeletedAt: pgtype.Timestamptz{
			Time:  data.DeletedAt,
			Valid: true,
		},
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrClientNotFound
		}
		return fmt.Errorf("%s: failed to delete app: %w", method, err)
	}
	return nil
}

func (s *ClientStorage) CheckClientIDExists(ctx context.Context, clientID string) error {
	const method = "storage.client.postgres.CheckClientIDExists"

	clientIDExists, err := s.Queries.CheckClientIDExists(ctx, clientID)
	if err != nil {
		return fmt.Errorf("%s: failed to check if client ID exists: %w", method, err)
	}
	if !clientIDExists {
		return storage.ErrClientIDDoesNotExist
	}
	return nil
}
