package entity

import (
	"time"

	"github.com/segmentio/ksuid"
)

type (
	Session struct {
		ID            string
		ClientID      string
		UserID        string
		DeviceID      string
		RefreshToken  string
		CreatedAt     time.Time
		LastVisitedAt time.Time
		ExpiresAt     time.Time
	}

	SessionRequestData struct {
		UserID     string
		DeviceID   string
		ClientID   string
		UserDevice UserDeviceRequestData
	}

	SessionMeta struct {
		ClientID  string
		UserID    string
		DeviceID  string
		CreatedAt time.Time
		ExpiresAt time.Time
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
		ClientID:      reqData.ClientID,
		UserID:        reqData.UserID,
		DeviceID:      reqData.DeviceID,
		RefreshToken:  refreshToken,
		CreatedAt:     currentTime,
		LastVisitedAt: currentTime,
		ExpiresAt:     currentTime.Add(refreshTokenTTL),
	}
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}
