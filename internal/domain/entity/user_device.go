package model

import "time"

type (
	Device struct {
		ID            string    `db:"id"`
		UserID        string    `db:"user_id"`
		AppID         string    `db:"app_id"`
		UserAgent     string    `db:"user_agent"`
		IP            string    `db:"ip"`
		Detached      bool      `db:"detached"`
		LastVisitedAt time.Time `db:"last_visited_at"`
		DetachedAt    time.Time `db:"detached_at"`
	}

	DeviceRequestData struct {
		UserAgent string
		IP        string
	}
)
