package model

import "time"

type Session struct {
	UserID        string
	AppID         string
	DeviceID      string
	RefreshToken  string
	LastVisitedAt time.Time
	ExpiresAt     time.Time
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}

type SessionService interface {
}
