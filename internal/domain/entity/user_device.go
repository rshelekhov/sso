package entity

import (
	"time"

	"github.com/segmentio/ksuid"
)

type (
	UserDevice struct {
		ID            string    `db:"id"`
		UserID        string    `db:"user_id"`
		AppID         string    `db:"app_id"`
		UserAgent     string    `db:"user_agent"`
		IP            string    `db:"ip"`
		Detached      bool      `db:"detached"`
		LastVisitedAt time.Time `db:"last_visited_at"`
		DetachedAt    time.Time `db:"detached_at"`
	}

	UserDeviceRequestData struct {
		UserAgent string
		IP        string
	}
)

func NewUserDevice(session SessionRequestData) UserDevice {
	return UserDevice{
		ID:            ksuid.New().String(),
		UserID:        session.UserID,
		AppID:         session.AppID,
		UserAgent:     session.UserDevice.UserAgent,
		IP:            session.UserDevice.IP,
		Detached:      false,
		LastVisitedAt: time.Now(),
	}
}
