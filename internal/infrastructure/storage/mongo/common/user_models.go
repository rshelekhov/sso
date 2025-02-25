package common

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
)

// Mongo document field names
const (
	FieldID           = "_id"
	FieldEmail        = "email"
	FieldAppID        = "app_id"
	FieldPasswordHash = "password_hash"
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
	AppID        string     `bson:"app_id"`
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
		AppID:        user.AppID,
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
		AppID:        doc.AppID,
		Verified:     doc.Verified,
		CreatedAt:    doc.CreatedAt,
		UpdatedAt:    doc.UpdatedAt,
	}
}
