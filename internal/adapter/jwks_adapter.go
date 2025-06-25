package adapter

import (
	"context"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/pkg/jwtauth"
)

type JWKSGetter interface {
	GetJWKS(ctx context.Context, clientID string) (entity.JWKS, error)
}

type JWKSAdapter struct {
	jwksGetter JWKSGetter
}

func NewJWKSAdapter(jwksGetter JWKSGetter) *JWKSAdapter {
	return &JWKSAdapter{
		jwksGetter: jwksGetter,
	}
}

func (a *JWKSAdapter) GetJWKS(ctx context.Context, clientID string) ([]jwtauth.JWK, error) {
	jwks, err := a.jwksGetter.GetJWKS(ctx, clientID)
	if err != nil {
		return nil, err
	}

	result := make([]jwtauth.JWK, len(jwks.Keys))
	for i, jwk := range jwks.Keys {
		result[i] = jwtauth.JWK{
			Alg: jwk.Alg,
			Kty: jwk.Kty,
			Use: jwk.Use,
			Kid: jwk.Kid,
			N:   jwk.N,
			E:   jwk.E,
		}
	}

	return result, nil
}
