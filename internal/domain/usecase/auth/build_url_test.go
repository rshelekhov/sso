package auth

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildVerificationURL(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
		token    string
		wantURL  string
	}{
		{
			name:     "simple URL",
			endpoint: "https://example.com/verify",
			token:    "abc123",
			wantURL:  "https://example.com/verify?token=abc123",
		},
		{
			name:     "URL with trailing slash",
			endpoint: "https://example.com/verify/",
			token:    "token123",
			wantURL:  "https://example.com/verify/?token=token123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := buildVerificationURL(tc.endpoint, tc.token)
			require.NoError(t, err)
			require.Equal(t, tc.wantURL, result)

			// Verify token is in query params
			parsedResult, err := url.Parse(result)
			require.NoError(t, err)
			require.Equal(t, tc.token, parsedResult.Query().Get("token"))
		})
	}
}

func TestBuildVerificationURL_PreservesExistingParams(t *testing.T) {
	endpoint := "https://example.com/verify?source=email&lang=en&utm_campaign=test"
	token := "mytoken123"

	result, err := buildVerificationURL(endpoint, token)
	require.NoError(t, err)

	parsedResult, err := url.Parse(result)
	require.NoError(t, err)

	// Check all params are present
	require.Equal(t, "email", parsedResult.Query().Get("source"))
	require.Equal(t, "en", parsedResult.Query().Get("lang"))
	require.Equal(t, "test", parsedResult.Query().Get("utm_campaign"))
	require.Equal(t, "mytoken123", parsedResult.Query().Get("token"))

	// Check we have exactly 4 params
	require.Len(t, parsedResult.Query(), 4)
}

func TestBuildVerificationURL_InvalidURL(t *testing.T) {
	_, err := buildVerificationURL("://invalid-url", "token")
	require.Error(t, err)
}
