package common

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

// Mongo document field names
const (
	FieldID           = "_id"
	FieldEmail        = "email"
	FieldPasswordHash = "password_hash"
	FieldClientID     = "client_id"
	FieldStatus       = "status"
	FieldVerified     = "verified"
	FieldCreatedAt    = "created_at"
	FieldUpdatedAt    = "updated_at"
	FieldDeletedAt    = "deleted_at"
)

type UserDocument struct {
	ID           string     `bson:"_id"`
	Email        string     `bson:"email"`
	PasswordHash string     `bson:"password_hash"`
	Name         string     `bson:"name"`
	Verified     bool       `bson:"verified"`
	CreatedAt    time.Time  `bson:"created_at"`
	UpdatedAt    time.Time  `bson:"updated_at"`
	DeletedAt    *time.Time `bson:"deleted_at,omitempty"`
}

func ToUserDoc(user entity.User) UserDocument {
	var deletedAt *time.Time
	if !user.DeletedAt.IsZero() {
		deletedAt = &user.DeletedAt
	}

	return UserDocument{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		Name:         user.Name,
		Verified:     user.Verified,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		DeletedAt:    deletedAt,
	}
}

func ToUserEntity(doc UserDocument) entity.User {
	return entity.User{
		ID:           doc.ID,
		Email:        doc.Email,
		PasswordHash: doc.PasswordHash,
		Name:         doc.Name,
		Verified:     doc.Verified,
		CreatedAt:    doc.CreatedAt,
		UpdatedAt:    doc.UpdatedAt,
	}
}
