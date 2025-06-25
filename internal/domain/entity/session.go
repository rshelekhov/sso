package entity

import (
	"time"

	"github.com/segmentio/ksuid"
)

type (
	Session struct {
		ID            string
		UserID        string
		DeviceID      string
		RefreshToken  string
		LastVisitedAt time.Time
		ExpiresAt     time.Time
	}

	SessionRequestData struct {
		UserID     string
		DeviceID   string
		ClientID   string
		UserDevice UserDeviceRequestData
	}

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
)

func NewSession(
	reqData SessionRequestData,
	refreshToken string,
	refreshTokenTTL time.Duration,
	currentTime time.Time,
) Session {
	return Session{
		ID:            ksuid.New().String(),
		UserID:        reqData.UserID,
		DeviceID:      reqData.DeviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: currentTime,
		ExpiresAt:     currentTime.Add(refreshTokenTTL),
	}
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}
