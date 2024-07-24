// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package sqlc

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type App struct {
	ID        string             `db:"id"`
	Name      string             `db:"name"`
	Secret    string             `db:"secret"`
	Status    int32              `db:"status"`
	CreatedAt time.Time          `db:"created_at"`
	UpdatedAt time.Time          `db:"updated_at"`
	DeletedAt pgtype.Timestamptz `db:"deleted_at"`
}

type AppStatus struct {
	ID    int32  `db:"id"`
	Title string `db:"title"`
}

type RefreshSession struct {
	ID            int32     `db:"id"`
	UserID        string    `db:"user_id"`
	AppID         string    `db:"app_id"`
	DeviceID      string    `db:"device_id"`
	RefreshToken  string    `db:"refresh_token"`
	LastVisitedAt time.Time `db:"last_visited_at"`
	ExpiresAt     time.Time `db:"expires_at"`
}

type Token struct {
	ID          int32     `db:"id"`
	Token       string    `db:"token"`
	UserID      string    `db:"user_id"`
	TokenTypeID int32     `db:"token_type_id"`
	AppID       string    `db:"app_id"`
	CreatedAt   time.Time `db:"created_at"`
	ExpiresAt   time.Time `db:"expires_at"`
}

type TokenType struct {
	ID    int32  `db:"id"`
	Title string `db:"title"`
}

type User struct {
	ID           string             `db:"id"`
	Email        string             `db:"email"`
	PasswordHash string             `db:"password_hash"`
	AppID        string             `db:"app_id"`
	Verified     pgtype.Bool        `db:"verified"`
	CreatedAt    time.Time          `db:"created_at"`
	UpdatedAt    time.Time          `db:"updated_at"`
	DeletedAt    pgtype.Timestamptz `db:"deleted_at"`
}

type UserDevice struct {
	ID            string             `db:"id"`
	UserID        string             `db:"user_id"`
	AppID         string             `db:"app_id"`
	UserAgent     string             `db:"user_agent"`
	Ip            string             `db:"ip"`
	Detached      bool               `db:"detached"`
	LastVisitedAt time.Time          `db:"last_visited_at"`
	DetachedAt    pgtype.Timestamptz `db:"detached_at"`
}
