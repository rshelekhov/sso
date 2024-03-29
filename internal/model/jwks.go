package model

type (
	JWKSRequestData struct {
		AppID int32
	}

	JWK struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}

	JWKS struct {
		Keys []JWK `json:"keys"`
	}
)
