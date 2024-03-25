package model

import "time"

type Session struct {
	UserID       string
	DeviceID     string
	AppID        int32
	RefreshToken string
	LastLoginAt  time.Time
	ExpiresAt    time.Time
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}
