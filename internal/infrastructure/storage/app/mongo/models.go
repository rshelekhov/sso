package mongo

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

type AppDoc struct {
	ID        string    `bson:"_id"`
	Name      string    `bson:"name"`
	Secret    string    `bson:"secret"`
	Status    int32     `bson:"status"`
	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
	DeletedAt time.Time `bson:"deleted_at"`
}

func toAppDoc(app entity.AppData) AppDoc {
	return AppDoc{
		ID:        app.ID,
		Name:      app.Name,
		Secret:    app.Secret,
		Status:    int32(app.Status),
		CreatedAt: app.CreatedAt,
		UpdatedAt: app.UpdatedAt,
		DeletedAt: app.DeletedAt,
	}
}
