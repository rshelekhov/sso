package entity

import (
	"time"

	"github.com/segmentio/ksuid"
)

type (
	UserDevice struct {
		ID            string
		UserID        string
		AppID         string
		UserAgent     string
		IP            string
		Detached      bool
		LastVisitedAt time.Time
		DetachedAt    time.Time
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
