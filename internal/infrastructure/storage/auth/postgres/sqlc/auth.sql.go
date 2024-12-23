// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: auth.sql

package sqlc

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

const markEmailVerified = `-- name: MarkEmailVerified :exec
UPDATE users
SET verified = TRUE
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL
`

type MarkEmailVerifiedParams struct {
	ID    string `db:"id"`
	AppID string `db:"app_id"`
}

func (q *Queries) MarkEmailVerified(ctx context.Context, arg MarkEmailVerifiedParams) error {
	_, err := q.db.Exec(ctx, markEmailVerified, arg.ID, arg.AppID)
	return err
}

const registerUser = `-- name: RegisterUser :exec
INSERT INTO users (id, email, password_hash, app_id, verified, created_at,updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`

type RegisterUserParams struct {
	ID           string      `db:"id"`
	Email        string      `db:"email"`
	PasswordHash string      `db:"password_hash"`
	AppID        string      `db:"app_id"`
	Verified     pgtype.Bool `db:"verified"`
	CreatedAt    time.Time   `db:"created_at"`
	UpdatedAt    time.Time   `db:"updated_at"`
}

func (q *Queries) RegisterUser(ctx context.Context, arg RegisterUserParams) error {
	_, err := q.db.Exec(ctx, registerUser,
		arg.ID,
		arg.Email,
		arg.PasswordHash,
		arg.AppID,
		arg.Verified,
		arg.CreatedAt,
		arg.UpdatedAt,
	)
	return err
}
