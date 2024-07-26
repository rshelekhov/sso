package model

import "time"

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
		UserDevice      UserDeviceRequestData
	}

	LogoutRequestData struct {
		AppID      string
		UserDevice UserDeviceRequestData
	}
)
