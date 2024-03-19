package model

import "time"

type (
	UserDevice struct {
		ID            string    `db:"id"`
		UserID        string    `db:"user_id"`
		UserAgent     string    `db:"user_agent"`
		IP            string    `db:"ip"`
		Detached      bool      `db:"detached"`
		LatestLoginAt time.Time `db:"latest_login_at"`
		DetachedAt    time.Time `db:"detached_at"`
	}

	UserDeviceRequestData struct {
		UserAgent string
		IP        string
	}
)
