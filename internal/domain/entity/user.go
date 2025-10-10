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
		Name         string
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
		Name            string
		UpdatedPassword string
		UserDevice      UserDeviceRequestData
	}
)

func NewUser(email, name, hash string) User {
	return User{
		ID:           ksuid.New().String(),
		Email:        email,
		Name:         name,
		PasswordHash: hash,
		Verified:     false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}
