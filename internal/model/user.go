package model

import "time"

type (
	User struct {
		ID           string
		Email        string
		PasswordHash string
		AppID        int32
		CreatedAt    time.Time
		UpdatedAt    time.Time
		DeletedAt    time.Time
	}

	UserRequestData struct {
		Email           string
		Password        string
		UpdatedPassword string
		AppID           int32
		UserDevice      UserDeviceRequestData
	}

	LogoutRequestData struct {
		AppID      int
		UserDevice UserDeviceRequestData
	}
)
