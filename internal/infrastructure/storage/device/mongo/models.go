package mongo

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

const (
	fieldID            = "_id"
	fieldUserID        = "user_id"
	fieldUserAgent     = "user_agent"
	fieldLastVisitedAt = "last_visited_at"
)

type deviceDocument struct {
	ID            string    `bson:"_id"`
	UserID        string    `bson:"user_id"`
	AppID         string    `bson:"app_id"`
	UserAgent     string    `bson:"user_agent"`
	IP            string    `bson:"ip"`
	Detached      bool      `bson:"detached"`
	LastVisitedAt time.Time `bson:"last_visited_at"`
	DetachedAt    time.Time `bson:"detached_at"`
}

func toDeviceDoc(device entity.UserDevice) deviceDocument {
	return deviceDocument{
		ID:            device.ID,
		UserID:        device.UserID,
		AppID:         device.AppID,
		UserAgent:     device.UserAgent,
		IP:            device.IP,
		Detached:      device.Detached,
		LastVisitedAt: device.LastVisitedAt,
		DetachedAt:    device.DetachedAt,
	}
}
