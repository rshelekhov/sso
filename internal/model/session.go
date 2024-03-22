package model

import "time"

type Session struct {
	UserID        string    `db:"user_id"`
	DeviceID      string    `db:"device_id"`
	RefreshToken  string    `db:"refresh_token"`
	LastVisitedAt time.Time `db:"last_visited_at"` // TODO: make sure that db has a correct column title
	ExpiresAt     time.Time `db:"expires_at"`
}

func (s Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}
