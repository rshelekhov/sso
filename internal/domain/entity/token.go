package entity

import (
	"time"
)

const (
	IssuerKey = "issuer"
)

type (
	// SessionTokens uses for creating user sessions
	SessionTokens struct {
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
		UserDevice   UserDeviceRequestData
	}
)

type VerificationTokenType int

const (
	TokenTypeVerifyEmail VerificationTokenType = iota
	TokenTypeResetPassword
)

// VerificationToken uses for creating tokens for verification email and reset password
type VerificationToken struct {
	Token     string
	UserID    string
	AppID     string
	Endpoint  string
	Email     string
	Type      VerificationTokenType
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewVerificationToken(
	token, endpoint string,
	user User,
	tokenType VerificationTokenType,
	expiryTime time.Duration,
) VerificationToken {
	currentTime := time.Now()

	return VerificationToken{
		Token:     token,
		UserID:    user.ID,
		AppID:     user.AppID,
		Endpoint:  endpoint,
		Email:     user.Email,
		Type:      tokenType,
		CreatedAt: currentTime,
		ExpiresAt: currentTime.Add(expiryTime),
	}
}
