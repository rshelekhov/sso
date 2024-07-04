package model

import "time"

type (
	JWKSRequestData struct {
		AppID string
	}

	JWK struct {
		Alg string `json:"alg,omitempty"` // The specific cryptographic algorithm used with the key.
		Kty string `json:"kty,omitempty"` // The family of cryptographic algorithms used with the key.
		Use string `json:"use,omitempty"` // How the key was meant to be used; sig represents the signature
		Kid string `json:"kid,omitempty"` // The unique identifier for the key.

		// For RSA keys
		N string `json:"n,omitempty"` // The modulus for the RSA public key
		E string `json:"e,omitempty"` // The exponent for the RSA public key.

		// For ECDSA keys
		Crv string `json:"crv,omitempty"` // The curve for the ECDSA public key
		X   string `json:"x,omitempty"`   // The x coordinate for the ECDSA public key
		Y   string `json:"y,omitempty"`   // The y coordinate for the ECDSA public key}
	}

	JWKS struct {
		Keys []JWK         `json:"keys"`
		TTL  time.Duration `json:"ttl"`
	}
)
