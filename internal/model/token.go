package model

import "time"

type TokenType int

const (
	TokenTypeVerifyEmail TokenType = iota
	TokenTypeResetPassword
)

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

	EmailVerificationData struct {
		VerificationToken string
		UserID            string
		AppID             string
		Endpoint          string
		Email             string
		Type              TokenType
		CreatedAt         time.Time
		ExpiresAt         time.Time
	}

	EmailVerificationRequestData struct {
		VerificationToken string
	}
)
