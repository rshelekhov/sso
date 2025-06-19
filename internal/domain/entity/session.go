package entity

import (
	"time"

	"github.com/segmentio/ksuid"
)

type (
	Session struct {
		ID            string
		UserID        string
		ClientID      string
		DeviceID      string
		RefreshToken  string
		LastVisitedAt time.Time
		ExpiresAt     time.Time
	}

	SessionRequestData struct {
		UserID     string
		ClientID   string
		DeviceID   string
		UserDevice UserDeviceRequestData
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
		ClientID:      reqData.ClientID,
		DeviceID:      reqData.DeviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: currentTime,
		ExpiresAt:     currentTime.Add(refreshTokenTTL),
	}
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}
