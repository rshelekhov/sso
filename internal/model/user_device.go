package model

import "time"

type (
	UserDevice struct {
		ID            string    `db:"id"`
		UserID        string    `db:"user_id"`
		AppID         int32     `db:"app_id"`
		UserAgent     string    `db:"user_agent"`
		IP            string    `db:"ip"`
		Detached      bool      `db:"detached"`
		LastVisitedAt time.Time `db:"last_visited_at"` // TODO: make sure that db has a correct column title
		DetachedAt    time.Time `db:"detached_at"`
	}

	UserDeviceRequestData struct {
		UserAgent string
		IP        string
	}
)
