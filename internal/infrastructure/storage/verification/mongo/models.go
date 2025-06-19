package mongo

import (
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	fieldAppID  = "client_id"
	fieldUserID = "user_id"
	fieldToken  = "token"
)

type tokenDocument struct {
	ID          primitive.ObjectID `bson:"_id"`
	Token       string             `bson:"token"`
	UserID      string             `bson:"user_id"`
	ClientID    string             `bson:"client_id"`
	Endpoint    string             `bson:"endpoint"`
	Recipient   string             `bson:"recipient"`
	TokenTypeID int32              `bson:"token_type_id"`
	CreatedAt   time.Time          `bson:"created_at"`
	ExpiresAt   time.Time          `bson:"expires_at"`
}

func toTokenDoc(token entity.VerificationToken) tokenDocument {
	return tokenDocument{
		ID:          primitive.NewObjectID(),
		Token:       token.Token,
		UserID:      token.UserID,
		ClientID:    token.ClientID,
		Endpoint:    token.Endpoint,
		Recipient:   token.Email,
		TokenTypeID: int32(token.Type),
		CreatedAt:   token.CreatedAt,
		ExpiresAt:   token.ExpiresAt,
	}
}

func toVerificationTokenEntity(doc tokenDocument) entity.VerificationToken {
	return entity.VerificationToken{
		Token:     doc.Token,
		UserID:    doc.UserID,
		ClientID:  doc.ClientID,
		Endpoint:  doc.Endpoint,
		Email:     doc.Recipient,
		Type:      entity.VerificationTokenType(doc.TokenTypeID),
		CreatedAt: doc.CreatedAt,
		ExpiresAt: doc.ExpiresAt,
	}
}
