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
	"github.com/rshelekhov/sso/internal/infrastructure/storage/app/postgres/sqlc"
)

type AppStorage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewAppStorage(pool *pgxpool.Pool) *AppStorage {
	queries := sqlc.New(pool)

	return &AppStorage{
		Pool:    pool,
		Queries: queries,
	}
}

const UniqueViolationErrorCode = "23505"

func (s *AppStorage) RegisterApp(ctx context.Context, data entity.AppData) error {
	const method = "storage.app.postgres.RegisterApp"

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

func (s *AppStorage) DeleteApp(ctx context.Context, data entity.AppData) error {
	const method = "storage.app.postgres.DeleteApp"

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

func (s *AppStorage) CheckAppIDExists(ctx context.Context, appID string) error {
	const method = "storage.app.postgres.CheckAppIDExists"

	appIDExists, err := s.Queries.CheckAppIDExists(ctx, appID)
	if err != nil {
		return fmt.Errorf("%s: failed to check if app ID exists: %w", method, err)
	}
	if !appIDExists {
		return storage.ErrAppIDDoesNotExist
	}
	return nil
}
