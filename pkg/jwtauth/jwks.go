package jwtauth

import (
	"context"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/pkg/jwtauth/cache"
)

// JWK represents a JSON Web Key structure containing the necessary fields
// for RSA public key construction
type JWK struct {
	Alg string `json:"alg,omitempty"` // The specific cryptographic algorithm used with the key.
	Kty string `json:"kty,omitempty"` // The family of cryptographic algorithms used with the key.
	Use string `json:"use,omitempty"` // How the key was meant to be used; sig represents the signature
	Kid string `json:"kid,omitempty"` // The unique identifier for the key.

	// For RSA keys
	N string `json:"n,omitempty"` // The modulus for the RSA public key
	E string `json:"e,omitempty"` // The exponent for the RSA public key.
}

// JWKSResponse represents the structure of the JWKS endpoint response
type JWKSResponse struct {
	Keys []JWK         `json:"keys"`
	TTL  time.Duration `json:"ttl"`
}

const JWKSCacheKey = "jwks"

// getJWK retrieves a JWK by its key ID (kid) from the cache or fetches new JWKS if needed
// Returns the matching JWK or an error if not found
func (m *manager) getJWK(ctx context.Context, clientID, kid string) (*JWK, error) {
	const op = "jwt.manager.getJWK"

	// Construct cache key using clientID
	cacheKey := createCacheKey(clientID)

	cachedJWKS, found := m.getCachedJWKS(cacheKey)
	if !found || len(cachedJWKS) == 0 {
		jwks, err := m.jwksProvider.GetJWKS(ctx, clientID)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to get JWKS: %w", op, err)
		}

		if len(jwks) == 0 {
			return nil, fmt.Errorf("%s: no JWKS found for clientID %s", op, clientID)
		}

		m.mu.Lock()
		m.jwksCache.Set(cacheKey, jwks, cache.DefaultExpiration)
		m.mu.Unlock()

		cachedJWKS = jwks
	}

	// Find the JWK with the matching key ID
	for _, jwk := range cachedJWKS {
		if jwk.Kid == kid {
			return &jwk, nil
		}
	}

	return nil, fmt.Errorf("%s: JWK with kid %s not found", op, kid)
}

// getCachedJWKS returns a cached JWKS from the cache or nil if not found
func (m *manager) getCachedJWKS(cacheKey string) ([]JWK, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if value, found := m.jwksCache.Get(cacheKey); found {
		if jwks, ok := value.([]JWK); ok {
			return jwks, true
		}
	}

	return nil, false
}

// createCacheKey creates a cache key based on the clientID
func createCacheKey(clientID string) string {
	return fmt.Sprintf("%s:%s", JWKSCacheKey, clientID)
}
