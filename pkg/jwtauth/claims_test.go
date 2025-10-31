package jwtauth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromMapClaims(t *testing.T) {
	tests := []struct {
		name     string
		input    jwt.MapClaims
		validate func(t *testing.T, claims *Claims)
	}{
		{
			name: "standard claims",
			input: jwt.MapClaims{
				"sub": "user-123",
				"iss": "sso-service",
				"aud": "my-app",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
				"iat": float64(time.Now().Unix()),
			},
			validate: func(t *testing.T, claims *Claims) {
				assert.Equal(t, "user-123", claims.Subject)
				assert.Equal(t, "sso-service", claims.Issuer)
				assert.NotNil(t, claims.ExpiresAt)
				assert.NotNil(t, claims.IssuedAt)
			},
		},
		{
			name: "custom SSO claims",
			input: jwt.MapClaims{
				"user_id":   "user-456",
				"email":     "test@example.com",
				"client_id": "app-123",
				"device_id": "device-789",
			},
			validate: func(t *testing.T, claims *Claims) {
				assert.Equal(t, "user-456", claims.UserID)
				assert.Equal(t, "test@example.com", claims.Email)
				assert.Equal(t, "app-123", claims.ClientID)
				assert.Equal(t, "device-789", claims.DeviceID)
			},
		},
		{
			name: "roles claim",
			input: jwt.MapClaims{
				"user_id": "user-123",
				"roles":   []any{"admin", "user", "moderator"},
			},
			validate: func(t *testing.T, claims *Claims) {
				require.Len(t, claims.Roles, 3)
				assert.Equal(t, "admin", claims.Roles[0])
				assert.Equal(t, "user", claims.Roles[1])
				assert.Equal(t, "moderator", claims.Roles[2])
			},
		},
		{
			name: "extra custom claims",
			input: jwt.MapClaims{
				"user_id":    "user-123",
				"department": "engineering",
				"user_level": float64(42),
				"is_premium": true,
			},
			validate: func(t *testing.T, claims *Claims) {
				assert.Equal(t, "user-123", claims.UserID)
				assert.Equal(t, "engineering", claims.Extra["department"])
				assert.Equal(t, float64(42), claims.Extra["user_level"])
				assert.Equal(t, true, claims.Extra["is_premium"])
			},
		},
		{
			name: "empty roles array",
			input: jwt.MapClaims{
				"user_id": "user-123",
				"roles":   []any{},
			},
			validate: func(t *testing.T, claims *Claims) {
				assert.Empty(t, claims.Roles)
			},
		},
		{
			name: "mixed type roles (should skip non-strings)",
			input: jwt.MapClaims{
				"user_id": "user-123",
				"roles":   []any{"admin", 123, "user", nil},
			},
			validate: func(t *testing.T, claims *Claims) {
				require.Len(t, claims.Roles, 2)
				assert.Equal(t, "admin", claims.Roles[0])
				assert.Equal(t, "user", claims.Roles[1])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := FromMapClaims(tt.input)
			require.NotNil(t, claims)
			tt.validate(t, claims)
		})
	}
}

func TestClaims_GetString(t *testing.T) {
	claims := &Claims{
		Extra: map[string]any{
			"string_field": "test_value",
			"int_field":    42,
			"bool_field":   true,
		},
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "existing string field",
			key:      "string_field",
			expected: "test_value",
		},
		{
			name:     "non-existing field",
			key:      "nonexistent",
			expected: "",
		},
		{
			name:     "int field (should return empty)",
			key:      "int_field",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.GetString(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClaims_GetInt64(t *testing.T) {
	claims := &Claims{
		Extra: map[string]any{
			"float_field":  float64(42.5),
			"int64_field":  int64(100),
			"int_field":    int(50),
			"string_field": "not_a_number",
		},
	}

	tests := []struct {
		name     string
		key      string
		expected int64
	}{
		{
			name:     "float64 field",
			key:      "float_field",
			expected: 42,
		},
		{
			name:     "int64 field",
			key:      "int64_field",
			expected: 100,
		},
		{
			name:     "int field",
			key:      "int_field",
			expected: 50,
		},
		{
			name:     "non-existing field",
			key:      "nonexistent",
			expected: 0,
		},
		{
			name:     "string field (should return 0)",
			key:      "string_field",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.GetInt64(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClaims_GetBool(t *testing.T) {
	claims := &Claims{
		Extra: map[string]any{
			"true_field":   true,
			"false_field":  false,
			"string_field": "not_a_bool",
		},
	}

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "true field",
			key:      "true_field",
			expected: true,
		},
		{
			name:     "false field",
			key:      "false_field",
			expected: false,
		},
		{
			name:     "non-existing field",
			key:      "nonexistent",
			expected: false,
		},
		{
			name:     "string field (should return false)",
			key:      "string_field",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.GetBool(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClaims_HasRole(t *testing.T) {
	claims := &Claims{
		Roles: []string{"admin", "user", "moderator"},
	}

	tests := []struct {
		name     string
		role     string
		expected bool
	}{
		{
			name:     "existing role admin",
			role:     "admin",
			expected: true,
		},
		{
			name:     "existing role user",
			role:     "user",
			expected: true,
		},
		{
			name:     "non-existing role",
			role:     "superadmin",
			expected: false,
		},
		{
			name:     "empty string",
			role:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := claims.HasRole(tt.role)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClaims_HasRole_EmptyRoles(t *testing.T) {
	claims := &Claims{
		Roles: []string{},
	}

	assert.False(t, claims.HasRole("admin"))
}

func TestClaims_HasRole_NilRoles(t *testing.T) {
	claims := &Claims{
		Roles: nil,
	}

	assert.False(t, claims.HasRole("admin"))
}

func TestClaimsFromContext(t *testing.T) {
	t.Run("claims present in context", func(t *testing.T) {
		expectedClaims := &Claims{
			UserID: "user-123",
			Email:  "test@example.com",
		}

		ctx := ClaimsToContext(context.Background(), expectedClaims)
		actualClaims := ClaimsFromContext(ctx)

		assert.Equal(t, expectedClaims, actualClaims)
	})

	t.Run("claims not present in context", func(t *testing.T) {
		ctx := context.Background()
		claims := ClaimsFromContext(ctx)

		assert.Nil(t, claims)
	})

	t.Run("wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ClaimsCtxKey, "not-a-claims-struct")
		claims := ClaimsFromContext(ctx)

		assert.Nil(t, claims)
	})
}

func TestClaimsToContext(t *testing.T) {
	claims := &Claims{
		UserID: "user-123",
		Email:  "test@example.com",
		Roles:  []string{"admin"},
	}

	ctx := ClaimsToContext(context.Background(), claims)

	retrievedClaims := ClaimsFromContext(ctx)
	require.NotNil(t, retrievedClaims)
	assert.Equal(t, claims.UserID, retrievedClaims.UserID)
	assert.Equal(t, claims.Email, retrievedClaims.Email)
	assert.Equal(t, claims.Roles, retrievedClaims.Roles)
}

func TestClaims_GetRolesFromExtra(t *testing.T) {
	tests := []struct {
		name      string
		extra     map[string]any
		fieldName string
		expected  []string
	}{
		{
			name: "roles as []any",
			extra: map[string]any{
				"permissions": []any{"read", "write", "delete"},
			},
			fieldName: "permissions",
			expected:  []string{"read", "write", "delete"},
		},
		{
			name: "roles as []string",
			extra: map[string]any{
				"groups": []string{"admins", "users"},
			},
			fieldName: "groups",
			expected:  []string{"admins", "users"},
		},
		{
			name: "non-existing field",
			extra: map[string]any{
				"other": "value",
			},
			fieldName: "permissions",
			expected:  []string{},
		},
		{
			name: "wrong type field",
			extra: map[string]any{
				"permissions": "not-an-array",
			},
			fieldName: "permissions",
			expected:  []string{},
		},
		{
			name: "mixed type array (should skip non-strings)",
			extra: map[string]any{
				"permissions": []any{"read", 123, "write", nil, "delete"},
			},
			fieldName: "permissions",
			expected:  []string{"read", "write", "delete"},
		},
		{
			name: "empty array",
			extra: map[string]any{
				"permissions": []any{},
			},
			fieldName: "permissions",
			expected:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{
				Extra: tt.extra,
			}

			result := claims.GetRolesFromExtra(tt.fieldName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromMapClaims_NoRoles(t *testing.T) {
	// Test that tokens without roles work fine
	mapClaims := jwt.MapClaims{
		"user_id": "user-123",
		"email":   "test@example.com",
		// No roles field
	}

	claims := FromMapClaims(mapClaims)

	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Nil(t, claims.Roles) // or Empty
	assert.False(t, claims.HasRole("admin"))
}

func TestFromMapClaims_CustomRolesField(t *testing.T) {
	// Test that custom role fields go into Extra
	mapClaims := jwt.MapClaims{
		"user_id":     "user-123",
		"permissions": []any{"read", "write"},
		"scopes":      []any{"api:read", "api:write"},
	}

	claims := FromMapClaims(mapClaims)

	// Standard roles field should be empty
	assert.Nil(t, claims.Roles)

	// But custom fields should be in Extra
	permissions := claims.GetRolesFromExtra("permissions")
	assert.Equal(t, []string{"read", "write"}, permissions)

	scopes := claims.GetRolesFromExtra("scopes")
	assert.Equal(t, []string{"api:read", "api:write"}, scopes)
}

func TestFromMapClaims_RealWorldScenario(t *testing.T) {
	// Simulate a real JWT token payload
	mapClaims := jwt.MapClaims{
		"sub":       "user-abc-123",
		"iss":       "https://sso.example.com",
		"aud":       "api-gateway",
		"exp":       float64(time.Now().Add(15 * time.Minute).Unix()),
		"iat":       float64(time.Now().Unix()),
		"user_id":   "user-abc-123",
		"email":     "john.doe@example.com",
		"client_id": "mobile-app",
		"device_id": "iphone-xyz",
		"roles":     []any{"user", "premium"},
		"tenant_id": "tenant-456",
		"locale":    "en-US",
		"premium":   true,
	}

	claims := FromMapClaims(mapClaims)

	// Verify standard claims
	assert.Equal(t, "user-abc-123", claims.Subject)
	assert.Equal(t, "https://sso.example.com", claims.Issuer)
	assert.NotNil(t, claims.ExpiresAt)
	assert.NotNil(t, claims.IssuedAt)

	// Verify custom SSO claims
	assert.Equal(t, "user-abc-123", claims.UserID)
	assert.Equal(t, "john.doe@example.com", claims.Email)
	assert.Equal(t, "mobile-app", claims.ClientID)
	assert.Equal(t, "iphone-xyz", claims.DeviceID)

	// Verify roles
	require.Len(t, claims.Roles, 2)
	assert.True(t, claims.HasRole("user"))
	assert.True(t, claims.HasRole("premium"))
	assert.False(t, claims.HasRole("admin"))

	// Verify extra claims
	assert.Equal(t, "tenant-456", claims.GetString("tenant_id"))
	assert.Equal(t, "en-US", claims.GetString("locale"))
	assert.True(t, claims.GetBool("premium"))
}
