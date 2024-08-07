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

const checkAppIDExists = `-- name: CheckAppIDExists :one
SELECT EXISTS(SELECT 1 FROM apps WHERE id = $1)
`

func (q *Queries) CheckAppIDExists(ctx context.Context, id string) (bool, error) {
	row := q.db.QueryRow(ctx, checkAppIDExists, id)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const createToken = `-- name: CreateToken :exec
INSERT INTO tokens (token, user_id, app_id, endpoint, recipient, token_type_id,  created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`

type CreateTokenParams struct {
	Token       string    `db:"token"`
	UserID      string    `db:"user_id"`
	AppID       string    `db:"app_id"`
	Endpoint    string    `db:"endpoint"`
	Recipient   string    `db:"recipient"`
	TokenTypeID int32     `db:"token_type_id"`
	CreatedAt   time.Time `db:"created_at"`
	ExpiresAt   time.Time `db:"expires_at"`
}

func (q *Queries) CreateToken(ctx context.Context, arg CreateTokenParams) error {
	_, err := q.db.Exec(ctx, createToken,
		arg.Token,
		arg.UserID,
		arg.AppID,
		arg.Endpoint,
		arg.Recipient,
		arg.TokenTypeID,
		arg.CreatedAt,
		arg.ExpiresAt,
	)
	return err
}

const createUserSession = `-- name: CreateUserSession :exec
INSERT INTO refresh_sessions (user_id, app_id, device_id, refresh_token, last_visited_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
`

type CreateUserSessionParams struct {
	UserID        string    `db:"user_id"`
	AppID         string    `db:"app_id"`
	DeviceID      string    `db:"device_id"`
	RefreshToken  string    `db:"refresh_token"`
	LastVisitedAt time.Time `db:"last_visited_at"`
	ExpiresAt     time.Time `db:"expires_at"`
}

func (q *Queries) CreateUserSession(ctx context.Context, arg CreateUserSessionParams) error {
	_, err := q.db.Exec(ctx, createUserSession,
		arg.UserID,
		arg.AppID,
		arg.DeviceID,
		arg.RefreshToken,
		arg.LastVisitedAt,
		arg.ExpiresAt,
	)
	return err
}

const deleteAllSessions = `-- name: DeleteAllSessions :exec
DELETE FROM refresh_sessions
WHERE user_id = $1
  AND app_id = $2
`

type DeleteAllSessionsParams struct {
	UserID string `db:"user_id"`
	AppID  string `db:"app_id"`
}

func (q *Queries) DeleteAllSessions(ctx context.Context, arg DeleteAllSessionsParams) error {
	_, err := q.db.Exec(ctx, deleteAllSessions, arg.UserID, arg.AppID)
	return err
}

const deleteAllTokens = `-- name: DeleteAllTokens :exec
DELETE FROM tokens
WHERE user_id = $1
  AND app_id = $2
`

type DeleteAllTokensParams struct {
	UserID string `db:"user_id"`
	AppID  string `db:"app_id"`
}

func (q *Queries) DeleteAllTokens(ctx context.Context, arg DeleteAllTokensParams) error {
	_, err := q.db.Exec(ctx, deleteAllTokens, arg.UserID, arg.AppID)
	return err
}

const deleteRefreshTokenFromSession = `-- name: DeleteRefreshTokenFromSession :exec
DELETE FROM refresh_sessions
WHERE refresh_token = $1
`

func (q *Queries) DeleteRefreshTokenFromSession(ctx context.Context, refreshToken string) error {
	_, err := q.db.Exec(ctx, deleteRefreshTokenFromSession, refreshToken)
	return err
}

const deleteSession = `-- name: DeleteSession :exec
DELETE FROM refresh_sessions
WHERE user_id = $1
  AND app_id = $2
  AND device_id = $3
`

type DeleteSessionParams struct {
	UserID   string `db:"user_id"`
	AppID    string `db:"app_id"`
	DeviceID string `db:"device_id"`
}

func (q *Queries) DeleteSession(ctx context.Context, arg DeleteSessionParams) error {
	_, err := q.db.Exec(ctx, deleteSession, arg.UserID, arg.AppID, arg.DeviceID)
	return err
}

const deleteToken = `-- name: DeleteToken :exec
DELETE FROM tokens
WHERE token = $1
`

func (q *Queries) DeleteToken(ctx context.Context, token string) error {
	_, err := q.db.Exec(ctx, deleteToken, token)
	return err
}

const deleteUser = `-- name: DeleteUser :exec
UPDATE users
SET deleted_at = $1
WHERE id = $2
  AND app_id = $3
  AND deleted_at IS NULL
`

type DeleteUserParams struct {
	DeletedAt pgtype.Timestamptz `db:"deleted_at"`
	ID        string             `db:"id"`
	AppID     string             `db:"app_id"`
}

func (q *Queries) DeleteUser(ctx context.Context, arg DeleteUserParams) error {
	_, err := q.db.Exec(ctx, deleteUser, arg.DeletedAt, arg.ID, arg.AppID)
	return err
}

const getSessionByRefreshToken = `-- name: GetSessionByRefreshToken :one
SELECT user_id, app_id, device_id, last_visited_at, expires_at
FROM refresh_sessions
WHERE refresh_token = $1
`

type GetSessionByRefreshTokenRow struct {
	UserID        string    `db:"user_id"`
	AppID         string    `db:"app_id"`
	DeviceID      string    `db:"device_id"`
	LastVisitedAt time.Time `db:"last_visited_at"`
	ExpiresAt     time.Time `db:"expires_at"`
}

func (q *Queries) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (GetSessionByRefreshTokenRow, error) {
	row := q.db.QueryRow(ctx, getSessionByRefreshToken, refreshToken)
	var i GetSessionByRefreshTokenRow
	err := row.Scan(
		&i.UserID,
		&i.AppID,
		&i.DeviceID,
		&i.LastVisitedAt,
		&i.ExpiresAt,
	)
	return i, err
}

const getTokenData = `-- name: GetTokenData :one
SELECT token, user_id, app_id, endpoint, token_type_id, recipient, expires_at
FROM tokens
WHERE token = $1
`

type GetTokenDataRow struct {
	Token       string    `db:"token"`
	UserID      string    `db:"user_id"`
	AppID       string    `db:"app_id"`
	Endpoint    string    `db:"endpoint"`
	TokenTypeID int32     `db:"token_type_id"`
	Recipient   string    `db:"recipient"`
	ExpiresAt   time.Time `db:"expires_at"`
}

func (q *Queries) GetTokenData(ctx context.Context, token string) (GetTokenDataRow, error) {
	row := q.db.QueryRow(ctx, getTokenData, token)
	var i GetTokenDataRow
	err := row.Scan(
		&i.Token,
		&i.UserID,
		&i.AppID,
		&i.Endpoint,
		&i.TokenTypeID,
		&i.Recipient,
		&i.ExpiresAt,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, email, app_id, updated_at
FROM users
WHERE email = $1
  AND app_id = $2
  AND deleted_at IS NULL
`

type GetUserByEmailParams struct {
	Email string `db:"email"`
	AppID string `db:"app_id"`
}

type GetUserByEmailRow struct {
	ID        string    `db:"id"`
	Email     string    `db:"email"`
	AppID     string    `db:"app_id"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (q *Queries) GetUserByEmail(ctx context.Context, arg GetUserByEmailParams) (GetUserByEmailRow, error) {
	row := q.db.QueryRow(ctx, getUserByEmail, arg.Email, arg.AppID)
	var i GetUserByEmailRow
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.AppID,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserByID = `-- name: GetUserByID :one
SELECT id, email, app_id, verified, updated_at
FROM users
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL
`

type GetUserByIDParams struct {
	ID    string `db:"id"`
	AppID string `db:"app_id"`
}

type GetUserByIDRow struct {
	ID        string      `db:"id"`
	Email     string      `db:"email"`
	AppID     string      `db:"app_id"`
	Verified  pgtype.Bool `db:"verified"`
	UpdatedAt time.Time   `db:"updated_at"`
}

func (q *Queries) GetUserByID(ctx context.Context, arg GetUserByIDParams) (GetUserByIDRow, error) {
	row := q.db.QueryRow(ctx, getUserByID, arg.ID, arg.AppID)
	var i GetUserByIDRow
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.AppID,
		&i.Verified,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserData = `-- name: GetUserData :one
SELECT id, email, password_hash, app_id, updated_at
FROM users
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL
`

type GetUserDataParams struct {
	ID    string `db:"id"`
	AppID string `db:"app_id"`
}

type GetUserDataRow struct {
	ID           string    `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"password_hash"`
	AppID        string    `db:"app_id"`
	UpdatedAt    time.Time `db:"updated_at"`
}

func (q *Queries) GetUserData(ctx context.Context, arg GetUserDataParams) (GetUserDataRow, error) {
	row := q.db.QueryRow(ctx, getUserData, arg.ID, arg.AppID)
	var i GetUserDataRow
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PasswordHash,
		&i.AppID,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserDeviceID = `-- name: GetUserDeviceID :one
SELECT id
FROM user_devices
WHERE user_id = $1
  AND user_agent = $2
  AND detached = FALSE
`

type GetUserDeviceIDParams struct {
	UserID    string `db:"user_id"`
	UserAgent string `db:"user_agent"`
}

func (q *Queries) GetUserDeviceID(ctx context.Context, arg GetUserDeviceIDParams) (string, error) {
	row := q.db.QueryRow(ctx, getUserDeviceID, arg.UserID, arg.UserAgent)
	var id string
	err := row.Scan(&id)
	return id, err
}

const getUserIDByToken = `-- name: GetUserIDByToken :one
SELECT user_id
FROM tokens
WHERE token = $1
`

func (q *Queries) GetUserIDByToken(ctx context.Context, token string) (string, error) {
	row := q.db.QueryRow(ctx, getUserIDByToken, token)
	var user_id string
	err := row.Scan(&user_id)
	return user_id, err
}

const getUserStatusByEmail = `-- name: GetUserStatusByEmail :one
SELECT CASE
WHEN EXISTS(
    SELECT 1
    FROM users
    WHERE users.email = $1
      AND deleted_at IS NULL
    ) THEN 'active'
    WHEN EXISTS(
    SELECT 1
    FROM users
    WHERE users.email = $1
      AND deleted_at IS NOT NULL
    ) THEN 'soft_deleted'
ELSE 'not_found' END AS status
`

func (q *Queries) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	row := q.db.QueryRow(ctx, getUserStatusByEmail, email)
	var status string
	err := row.Scan(&status)
	return status, err
}

const getUserStatusByID = `-- name: GetUserStatusByID :one
SELECT CASE
WHEN EXISTS(
    SELECT 1
    FROM users
    WHERE users.id = $1
        AND deleted_at IS NULL
        ) THEN 'active'
    WHEN EXISTS(
    SELECT 1
    FROM users
    WHERE users.id = $1
        AND deleted_at IS NOT NULL
    ) THEN 'soft_deleted'
ELSE 'not_found' END AS status
`

func (q *Queries) GetUserStatusByID(ctx context.Context, id string) (string, error) {
	row := q.db.QueryRow(ctx, getUserStatusByID, id)
	var status string
	err := row.Scan(&status)
	return status, err
}

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

const registerDevice = `-- name: RegisterDevice :exec
INSERT INTO user_devices (id, user_id, app_id, user_agent, ip, detached, last_visited_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`

type RegisterDeviceParams struct {
	ID            string    `db:"id"`
	UserID        string    `db:"user_id"`
	AppID         string    `db:"app_id"`
	UserAgent     string    `db:"user_agent"`
	Ip            string    `db:"ip"`
	Detached      bool      `db:"detached"`
	LastVisitedAt time.Time `db:"last_visited_at"`
}

func (q *Queries) RegisterDevice(ctx context.Context, arg RegisterDeviceParams) error {
	_, err := q.db.Exec(ctx, registerDevice,
		arg.ID,
		arg.UserID,
		arg.AppID,
		arg.UserAgent,
		arg.Ip,
		arg.Detached,
		arg.LastVisitedAt,
	)
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

const updateLatestLoginAt = `-- name: UpdateLatestLoginAt :exec
UPDATE user_devices
SET last_visited_at = $1
WHERE id = $2
  AND app_id = $3
`

type UpdateLatestLoginAtParams struct {
	LastVisitedAt time.Time `db:"last_visited_at"`
	ID            string    `db:"id"`
	AppID         string    `db:"app_id"`
}

func (q *Queries) UpdateLatestLoginAt(ctx context.Context, arg UpdateLatestLoginAtParams) error {
	_, err := q.db.Exec(ctx, updateLatestLoginAt, arg.LastVisitedAt, arg.ID, arg.AppID)
	return err
}
