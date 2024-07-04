package model

import "time"

type (
	TokenData struct {
		AccessToken      string
		RefreshToken     string
		Domain           string
		Path             string
		ExpiresAt        time.Time
		HTTPOnly         bool
		AdditionalFields map[string]string
	}

	RefreshRequestData struct {
		RefreshToken string
		AppID        string
		UserDevice   UserDeviceRequestData
	}
)
