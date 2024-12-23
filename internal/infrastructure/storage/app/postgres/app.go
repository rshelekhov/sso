package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/infrastructure/storage"
	"github.com/rshelekhov/sso/src/infrastructure/storage/app/postgres/sqlc"
)

type Storage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewAppStorage(pool *pgxpool.Pool) *Storage {
	return &Storage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

const UniqueViolationErrorCode = "23505"

func (s *Storage) RegisterApp(ctx context.Context, data entity.AppData) error {
	const method = "user.storage.RegisterApp"

	if err := s.Queries.InsertApp(ctx, sqlc.InsertAppParams{
		ID:        data.ID,
		Name:      data.Name,
		Secret:    data.Secret,
		Status:    int32(data.Status),
		CreatedAt: data.CreatedAt,
		UpdatedAt: data.UpdatedAt,
	}); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == UniqueViolationErrorCode {
			return storage.ErrAppAlreadyExists
		}
		return fmt.Errorf("%s: failed to insert app: %w", method, err)
	}
	return nil
}

func (s *Storage) DeleteApp(ctx context.Context, data entity.AppData) error {
	const method = "user.storage.DeleteApp"

	if err := s.Queries.DeleteApp(ctx, sqlc.DeleteAppParams{
		ID:     data.ID,
		Secret: data.Secret,
		DeletedAt: pgtype.Timestamptz{
			Time:  data.DeletedAt,
			Valid: true,
		},
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrAppNotFound
		}
		return fmt.Errorf("%s: failed to delete app: %w", method, err)
	}
	return nil
}

func (s *Storage) CheckAppIDExists(ctx context.Context, appID string) error {
	const method = "user.storage.CheckAppIDExists"

	appIDExists, err := s.Queries.CheckAppIDExists(ctx, appID)
	if err != nil {
		return fmt.Errorf("%s: failed to check if app ID exists: %w", method, err)
	}
	if !appIDExists {
		return storage.ErrAppIDDoesNotExist
	}
	return nil
}
