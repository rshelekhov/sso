package entity

import "time"

type (
	Session struct {
		UserID        string
		AppID         string
		DeviceID      string
		RefreshToken  string
		LastVisitedAt time.Time
		ExpiresAt     time.Time
	}

	SessionRequestData struct {
		UserID     string
		AppID      string
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
		UserID:        reqData.UserID,
		AppID:         reqData.AppID,
		DeviceID:      reqData.DeviceID,
		RefreshToken:  refreshToken,
		LastVisitedAt: currentTime,
		ExpiresAt:     currentTime.Add(refreshTokenTTL),
	}
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}
