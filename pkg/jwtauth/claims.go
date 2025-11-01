package jwtauth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	ClaimsCtxKey contextKey = "Claims"
)

var knownClaims = map[string]bool{
	"sub":       true,
	"iss":       true,
	"aud":       true,
	"exp":       true,
	"iat":       true,
	"nbf":       true,
	UserIDKey:   true,
	"email":     true,
	"client_id": true,
	"device_id": true,
	"roles":     true,
}

// Claims represents the standard JWT claims that are commonly used in the SSO system.
// This struct can be extended to include custom claims as needed.
type Claims struct {
	// Standard JWT claims
	jwt.RegisteredClaims

	// Custom claims
	UserID   string   `json:"user_id"`
	Email    string   `json:"email,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	DeviceID string   `json:"device_id,omitempty"`

	// Raw claims map for any additional custom claims
	Extra map[string]any `json:"-"`
}

// FromMapClaims converts jwt.MapClaims to our structured Claims type.
// This allows us to work with strongly-typed claims while preserving flexibility.
func FromMapClaims(mapClaims jwt.MapClaims) *Claims {
	claims := &Claims{
		Extra: make(map[string]any),
	}

	extractStandardRegisteredClaims(claims, mapClaims)

	extractCustomClaims(claims, mapClaims)

	extractRoles(claims, mapClaims)

	extractExtraClaims(claims, mapClaims)

	return claims
}

func extractStandardRegisteredClaims(claims *Claims, mapClaims jwt.MapClaims) {
	extractStringClaim(&claims.Subject, mapClaims, "sub")
	extractStringClaim(&claims.Issuer, mapClaims, "iss")
	extractAudienceClaim(claims, mapClaims)
	extractTimeClaim(&claims.ExpiresAt, mapClaims, "exp")
	extractTimeClaim(&claims.IssuedAt, mapClaims, "iat")
	extractTimeClaim(&claims.NotBefore, mapClaims, "nbf")
}

func extractStringClaim(target *string, mapClaims jwt.MapClaims, key string) {
	if value, ok := mapClaims[key].(string); ok {
		*target = value
	}
}

func extractAudienceClaim(claims *Claims, mapClaims jwt.MapClaims) {
	aud, ok := mapClaims["aud"]
	if !ok {
		return
	}

	switch v := aud.(type) {
	case string:
		claims.Audience = jwt.ClaimStrings{v}
	case []any:
		auds := make([]string, 0, len(v))
		for _, a := range v {
			if audStr, ok := a.(string); ok {
				auds = append(auds, audStr)
			}
		}
		claims.Audience = auds
	}
}

func extractTimeClaim(target **jwt.NumericDate, mapClaims jwt.MapClaims, key string) {
	value, ok := mapClaims[key]
	if !ok {
		return
	}

	switch v := value.(type) {
	case float64:
		*target = jwt.NewNumericDate(time.Unix(int64(v), 0))
	case json.Number:
		if ts, err := v.Int64(); err == nil {
			*target = jwt.NewNumericDate(time.Unix(ts, 0))
		}
	}
}

func extractCustomClaims(claims *Claims, mapClaims jwt.MapClaims) {
	if userID, ok := mapClaims[UserIDKey].(string); ok {
		claims.UserID = userID
	}

	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}

	if clientID, ok := mapClaims["client_id"].(string); ok {
		claims.ClientID = clientID
	}

	if deviceID, ok := mapClaims["device_id"].(string); ok {
		claims.DeviceID = deviceID
	}
}

func extractRoles(claims *Claims, mapClaims jwt.MapClaims) {
	if rolesRaw, ok := mapClaims["roles"]; ok {
		if rolesArray, ok := rolesRaw.([]any); ok {
			roles := make([]string, 0, len(rolesArray))

			for _, role := range rolesArray {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, roleStr)
				}
			}
			claims.Roles = roles
		}
	}
}

func extractExtraClaims(claims *Claims, mapClaims jwt.MapClaims) {
	for key, value := range mapClaims {
		if !knownClaims[key] {
			claims.Extra[key] = value
		}
	}
}

// GetString retrieves a string value from Extra claims.
// Returns empty string if the claim doesn't exist or is not a string.
func (c *Claims) GetString(key string) string {
	if val, ok := c.Extra[key].(string); ok {
		return val
	}
	return ""
}

// GetInt64 retrieves an int64 value from Extra claims.
// Returns 0 if the claim doesn't exist or cannot be converted to int64.
func (c *Claims) GetInt64(key string) int64 {
	switch val := c.Extra[key].(type) {
	case float64:
		return int64(val)
	case int64:
		return val
	case int:
		return int64(val)
	default:
		return 0
	}
}

// GetBool retrieves a boolean value from Extra claims.
// Returns false if the claim doesn't exist or is not a boolean.
func (c *Claims) GetBool(key string) bool {
	if val, ok := c.Extra[key].(bool); ok {
		return val
	}
	return false
}

// HasRole checks if the user has a specific role.
// Returns false if Roles is nil or empty.
func (c *Claims) HasRole(role string) bool {
	if c.Roles == nil {
		return false
	}

	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// GetRolesFromExtra retrieves roles from a custom claim field.
// This is useful when different clients use different field names for roles
// (e.g., "permissions", "groups", "scopes").
// Returns empty slice if the field doesn't exist or is not a string array.
func (c *Claims) GetRolesFromExtra(fieldName string) []string {
	rolesRaw, ok := c.Extra[fieldName]
	if !ok {
		return []string{}
	}

	switch v := rolesRaw.(type) {
	case []any:
		roles := make([]string, 0, len(v))

		for _, role := range v {
			if roleStr, ok := role.(string); ok {
				roles = append(roles, roleStr)
			}
		}
		return roles
	case []string:
		return v
	default:
		return []string{}
	}
}

// ClaimsFromContext retrieves claims from context.
// Returns nil if claims are not found in context.
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(ClaimsCtxKey).(*Claims)
	return claims
}

// MustGetClaims retrieves claims from context and returns an error if not found.
// This is useful when you want explicit error handling instead of nil checks.
func MustGetClaims(ctx context.Context) (*Claims, error) {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return nil, ErrTokenNotFoundInContext
	}
	return claims, nil
}

// ClaimsToContext adds claims to the context.
func ClaimsToContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ClaimsCtxKey, claims)
}
