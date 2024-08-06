package model

import "time"

type (
	// AuthTokenData uses for creating user sessions
	AuthTokenData struct {
		AccessToken      string
		RefreshToken     string
		Domain           string
		Path             string
		ExpiresAt        time.Time
		HTTPOnly         bool
		AdditionalFields map[string]string
	}

	RefreshTokenRequestData struct {
		RefreshToken string
		AppID        string
		UserDevice   UserDeviceRequestData
	}
)

type TokenType int

const (
	TokenTypeVerifyEmail TokenType = iota
	TokenTypeResetPassword
)

// TokenData uses for creating tokens for verification email and reset password
type TokenData struct {
	Token     string
	UserID    string
	AppID     string
	Endpoint  string
	Email     string
	Type      TokenType
	CreatedAt time.Time
	ExpiresAt time.Time
}
