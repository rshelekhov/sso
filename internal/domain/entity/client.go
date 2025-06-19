package entity

import "time"

type clientStatusType int

const (
	ClientStatusInactive clientStatusType = iota
	ClientStatusActive
	ClientStatusDeleted
)

type ClientData struct {
	ID        string
	Name      string
	Secret    string
	Status    clientStatusType
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt time.Time
}
