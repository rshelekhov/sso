package entity

import "time"

type appStatusType int

const (
	AppStatusInactive appStatusType = iota
	AppStatusActive
	AppStatusDeleted
)

type (
	AppData struct {
		ID        string
		Name      string
		Secret    string
		Status    appStatusType
		CreatedAt time.Time
		UpdatedAt time.Time
		DeletedAt time.Time
	}
)
