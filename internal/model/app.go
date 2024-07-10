package model

import "time"

type statusType int

const (
	StatusInactive statusType = iota
	StatusActive
	StatusDeleted
)

type (
	AppData struct {
		ID        string
		Name      string
		Secret    string
		Status    statusType
		CreatedAt time.Time
		UpdatedAt time.Time
		DeletedAt time.Time
	}

	AppRequestData struct {
		Name string
	}
)
