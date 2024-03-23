package model

import "time"

type (
	User struct {
		ID           string
		Email        string
		PasswordHash string
		UpdatedAt    time.Time
	}

	UserRequestData struct {
		Email      string
		Password   string
		AppID      int
		UserDevice UserDeviceRequestData
	}
)
