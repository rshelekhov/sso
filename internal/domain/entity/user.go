package model

import "time"

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
		AppID           string
		UserDevice      DeviceRequestData
	}

	LogoutRequestData struct {
		AppID      string
		UserDevice DeviceRequestData
	}
)
