package model

import "time"

type (
	TokenData struct {
		AccessToken      string
		RefreshToken     string
		Kid              string
		Domain           string
		Path             string
		ExpiresAt        time.Time
		HTTPOnly         bool
		AdditionalFields map[string]string
	}

	RefreshRequestData struct {
		RefreshToken string
		AppID        int32
		UserDevice   UserDeviceRequestData
	}
)
