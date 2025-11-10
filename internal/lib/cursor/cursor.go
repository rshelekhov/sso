package cursor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// SearchCursor represents a cursor for pagination in search results.
// It contains the creation timestamp and user ID of the last item in the current page.
type SearchCursor struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id"`
}

// Encode serializes the cursor to a base64-encoded JSON string for use as a page token.
// Returns empty string if cursor is nil.
func Encode(cursor *SearchCursor) (string, error) {
	if cursor == nil {
		return "", nil
	}

	jsonData, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("failed to marshal cursor: %w", err)
	}

	encoded := base64.URLEncoding.EncodeToString(jsonData)
	return encoded, nil
}

// Decode deserializes a base64-encoded JSON string into a SearchCursor.
// Returns nil if token is empty.
// Validates that the cursor timestamp is not in the future and UserID is a valid KSUID.
func Decode(token string) (*SearchCursor, error) {
	if token == "" {
		return nil, nil
	}

	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor token: failed to decode base64: %w", err)
	}

	var cursor SearchCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return nil, fmt.Errorf("invalid cursor token: failed to unmarshal JSON: %w", err)
	}

	if err := validate(&cursor); err != nil {
		return nil, err
	}

	return &cursor, nil
}

// validate checks that the cursor contains valid data.
func validate(cursor *SearchCursor) error {
	// Check that timestamp is not in the future (with 1 minute tolerance for clock skew)
	if cursor.CreatedAt.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("invalid cursor: timestamp is in the future")
	}

	// Validate that UserID is a valid KSUID (27 characters, base62-encoded)
	if len(cursor.UserID) != 27 {
		return fmt.Errorf("invalid cursor: user_id must be 27 characters (got %d)", len(cursor.UserID))
	}

	// Validate base62 characters [0-9A-Za-z]
	for _, c := range cursor.UserID {
		isValid := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if !isValid {
			return fmt.Errorf("invalid cursor: user_id contains invalid characters (expected base62)")
		}
	}

	return nil
}
