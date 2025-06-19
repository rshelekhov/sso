package mongo

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

const (
	fieldID            = "_id"
	fieldUserID        = "user_id"
	fieldAppID         = "client_id"
	fieldUserAgent     = "user_agent"
	fieldLastVisitedAt = "last_visited_at"
)

type deviceDocument struct {
	ID            string    `bson:"_id"`
	UserID        string    `bson:"user_id"`
	ClientID      string    `bson:"client_id"`
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
		ClientID:      device.ClientID,
		UserAgent:     device.UserAgent,
		IP:            device.IP,
		Detached:      device.Detached,
		LastVisitedAt: device.LastVisitedAt,
		DetachedAt:    device.DetachedAt,
	}
}
