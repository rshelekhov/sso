package entity

import (
	"github.com/segmentio/ksuid"
	"time"
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
		AppID        string
		Verified     bool
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

func NewUser(email, hash, appID string) User {
	return User{
		ID:           ksuid.New().String(),
		Email:        email,
		PasswordHash: hash,
		AppID:        appID,
		Verified:     false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}
