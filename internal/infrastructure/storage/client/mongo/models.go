package mongo

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

const (
	fieldID        = "_id"
	fieldName      = "name"
	fieldSecret    = "secret"
	fieldDeletedAt = "deleted_at"
)

type clientDocument struct {
	ID        string    `bson:"_id"`
	Name      string    `bson:"name"`
	Secret    string    `bson:"secret"`
	Status    int32     `bson:"status"`
	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
	DeletedAt time.Time `bson:"deleted_at"`
}

func toClientDoc(client entity.ClientData) clientDocument {
	return clientDocument{
		ID:        client.ID,
		Name:      client.Name,
		Secret:    client.Secret,
		Status:    int32(client.Status),
		CreatedAt: client.CreatedAt,
		UpdatedAt: client.UpdatedAt,
		DeletedAt: client.DeletedAt,
	}
}
