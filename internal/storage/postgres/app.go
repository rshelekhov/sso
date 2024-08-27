package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/storage/postgres/sqlc"
)

type AppStorage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewAppStorage(pool *pgxpool.Pool) *AppStorage {
	return &AppStorage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

const UniqueViolationErrorCode = "23505"

func (s *AppStorage) RegisterApp(ctx context.Context, data model.AppData) error {
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
			return le.ErrAppAlreadyExists
		}
		return fmt.Errorf("%s: failed to insert app: %w", method, err)
	}
	return nil
}

func (s *AppStorage) DeleteApp(ctx context.Context, data model.AppData) error {
	const method = "user.storage.DeleteApp"

	if err := s.Queries.DeleteApp(ctx, sqlc.DeleteAppParams{
		ID:     data.ID,
		Secret: data.Secret,
		DeletedAt: pgtype.Timestamptz{
			Time:  data.DeletedAt,
			Valid: true,
		},
	}); err != nil {
		return fmt.Errorf("%s: failed to delete app: %w", method, err)
	}
	return nil
}
