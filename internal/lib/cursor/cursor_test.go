package cursor

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	t.Run("successfully encodes valid cursor", func(t *testing.T) {
		userID := "2bxHvsjfPzGjdS7PGmvnKYXzCPD"
		createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

		cursor := &SearchCursor{
			CreatedAt: createdAt,
			UserID:    userID,
		}

		token, err := Encode(cursor)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify it's valid base64
		_, err = base64.URLEncoding.DecodeString(token)
		assert.NoError(t, err)
	})

	t.Run("returns empty string for nil cursor", func(t *testing.T) {
		token, err := Encode(nil)
		require.NoError(t, err)
		assert.Empty(t, token)
	})

	t.Run("encoded token can be decoded back", func(t *testing.T) {
		userID := "2bxHvsjfPzGjdS7PGmvnKYXzCPD"
		createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

		original := &SearchCursor{
			CreatedAt: createdAt,
			UserID:    userID,
		}

		token, err := Encode(original)
		require.NoError(t, err)

		decoded, err := Decode(token)
		require.NoError(t, err)
		assert.Equal(t, original.UserID, decoded.UserID)
		assert.True(t, original.CreatedAt.Equal(decoded.CreatedAt))
	})
}

func TestDecode(t *testing.T) {
	t.Run("successfully decodes valid token", func(t *testing.T) {
		userID := "2bxHvsjfPzGjdS7PGmvnKYXzCPD"
		createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

		cursor := &SearchCursor{
			CreatedAt: createdAt,
			UserID:    userID,
		}

		token, err := Encode(cursor)
		require.NoError(t, err)

		decoded, err := Decode(token)
		require.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, userID, decoded.UserID)
		assert.True(t, createdAt.Equal(decoded.CreatedAt))
	})

	t.Run("returns nil for empty token", func(t *testing.T) {
		decoded, err := Decode("")
		require.NoError(t, err)
		assert.Nil(t, decoded)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		invalidToken := "not-valid-base64!!!"
		decoded, err := Decode(invalidToken)
		assert.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		// Encode invalid JSON as base64
		invalidJSON := base64.URLEncoding.EncodeToString([]byte("{invalid json"))
		decoded, err := Decode(invalidJSON)
		assert.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "failed to unmarshal JSON")
	})

	t.Run("returns error for future timestamp", func(t *testing.T) {
		futureTime := time.Now().Add(2 * time.Hour)
		cursor := &SearchCursor{
			CreatedAt: futureTime,
			UserID:    "2bxHvsjfPzGjdS7PGmvnKYXzCPD",
		}

		token, err := Encode(cursor)
		require.NoError(t, err)

		decoded, err := Decode(token)
		assert.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "timestamp is in the future")
	})

	t.Run("allows timestamp with small clock skew tolerance", func(t *testing.T) {
		// Time 30 seconds in the future (within 1 minute tolerance)
		nearFutureTime := time.Now().Add(30 * time.Second)
		cursor := &SearchCursor{
			CreatedAt: nearFutureTime,
			UserID:    "2bxHvsjfPzGjdS7PGmvnKYXzCPD",
		}

		token, err := Encode(cursor)
		require.NoError(t, err)

		decoded, err := Decode(token)
		require.NoError(t, err)
		assert.NotNil(t, decoded)
	})

	t.Run("returns error for invalid KSUID - wrong length", func(t *testing.T) {
		cursor := &SearchCursor{
			CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			UserID:    "short",
		}

		token, err := Encode(cursor)
		require.NoError(t, err)

		decoded, err := Decode(token)
		assert.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "user_id must be 27 characters")
	})

	t.Run("returns error for invalid KSUID - special characters", func(t *testing.T) {
		cursor := &SearchCursor{
			CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			UserID:    "2bxHvsjfPzGjdS7PGmvnKYXz@#$",
		}

		token, err := Encode(cursor)
		require.NoError(t, err)

		decoded, err := Decode(token)
		assert.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "invalid characters")
	})

	t.Run("returns error for empty KSUID", func(t *testing.T) {
		cursor := &SearchCursor{
			CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			UserID:    "",
		}

		token, err := Encode(cursor)
		require.NoError(t, err)

		decoded, err := Decode(token)
		assert.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "user_id must be 27 characters")
	})
}

func TestValidate(t *testing.T) {
	t.Run("accepts valid cursor", func(t *testing.T) {
		cursor := &SearchCursor{
			CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			UserID:    "2bxHvsjfPzGjdS7PGmvnKYXzCPD",
		}

		err := validate(cursor)
		assert.NoError(t, err)
	})

	t.Run("rejects future timestamp beyond tolerance", func(t *testing.T) {
		cursor := &SearchCursor{
			CreatedAt: time.Now().Add(2 * time.Hour),
			UserID:    "2bxHvsjfPzGjdS7PGmvnKYXzCPD",
		}

		err := validate(cursor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timestamp is in the future")
	})

	t.Run("rejects invalid KSUID - wrong length", func(t *testing.T) {
		cursor := &SearchCursor{
			CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			UserID:    "toolong2bxHvsjfPzGjdS7PGmvnKYXzCPD",
		}

		err := validate(cursor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user_id must be 27 characters")
	})

	t.Run("rejects invalid KSUID - invalid characters", func(t *testing.T) {
		cursor := &SearchCursor{
			CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			UserID:    "2bxHvsjfPzGjdS7PGmvnKYXz@#$",
		}

		err := validate(cursor)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid characters")
	})
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	testCases := []struct {
		name      string
		userID    string
		createdAt time.Time
	}{
		{
			name:      "recent timestamp",
			userID:    "2bxHvsjfPzGjdS7PGmvnKYXzCPD",
			createdAt: time.Now().Add(-1 * time.Hour),
		},
		{
			name:      "old timestamp",
			userID:    "2bxKxpYvXVqL3hVfQC7kMNqNmAy",
			createdAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "timestamp with nanoseconds",
			userID:    "2bxM8TnLbNtJ4DpQW9XvRj3zNmP",
			createdAt: time.Date(2024, 3, 15, 14, 30, 45, 123456789, time.UTC),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := &SearchCursor{
				CreatedAt: tc.createdAt,
				UserID:    tc.userID,
			}

			// Encode
			token, err := Encode(original)
			require.NoError(t, err)
			assert.NotEmpty(t, token)

			// Decode
			decoded, err := Decode(token)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			// Verify
			assert.Equal(t, original.UserID, decoded.UserID)
			assert.True(t, original.CreatedAt.Equal(decoded.CreatedAt))
		})
	}
}
