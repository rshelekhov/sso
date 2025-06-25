package entity

import (
	"time"

	"github.com/segmentio/ksuid"
)

type userStatusType string

const (
	UserStatusActive      userStatusType = "active"
	UserStatusSoftDeleted userStatusType = "soft_deleted"
	UserStatusNotFound    userStatusType = "not_found"
)

func (u userStatusType) String() string {
	return string(u)
}

type (
	User struct {
		ID           string
		Email        string
		PasswordHash string
		Verified     bool
		Status       userStatusType
		CreatedAt    time.Time
		UpdatedAt    time.Time
		DeletedAt    time.Time
	}

	UserRequestData struct {
		Email           string
		Password        string
		UpdatedPassword string
		UserDevice      UserDeviceRequestData
	}
)

func NewUser(email, hash string) User {
	return User{
		ID:           ksuid.New().String(),
		Email:        email,
		PasswordHash: hash,
		Verified:     false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}
