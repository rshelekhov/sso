package mongo

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

const (
	fieldID            = "_id"
	fieldAppID         = "app_id"
	fieldUserID        = "user_id"
	fieldUserAgent     = "user_agent"
	fieldDeviceID      = "device_id"
	fieldRefreshToken  = "refresh_token"
	fieldLastVisitedAt = "last_visited_at"
)

type sessionDocument struct {
	ID            string    `bson:"_id"`
	UserID        string    `bson:"user_id"`
	AppID         string    `bson:"app_id"`
	DeviceID      string    `bson:"device_id"`
	RefreshToken  string    `bson:"refresh_token"`
	LastVisitedAt time.Time `bson:"last_visited_at"`
	ExpiresAt     time.Time `bson:"expires_at"`
}

func toSessionDoc(session entity.Session) sessionDocument {
	return sessionDocument{
		ID:            session.ID,
		UserID:        session.UserID,
		AppID:         session.AppID,
		DeviceID:      session.DeviceID,
		RefreshToken:  session.RefreshToken,
		LastVisitedAt: session.LastVisitedAt,
		ExpiresAt:     session.ExpiresAt,
	}
}

func toSessionEntity(doc sessionDocument) entity.Session {
	return entity.Session{
		UserID:        doc.UserID,
		AppID:         doc.AppID,
		DeviceID:      doc.DeviceID,
		RefreshToken:  doc.RefreshToken,
		LastVisitedAt: doc.LastVisitedAt,
		ExpiresAt:     doc.ExpiresAt,
	}
}

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
