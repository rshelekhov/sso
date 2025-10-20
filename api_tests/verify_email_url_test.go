package api_tests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// TestVerifyEmail_URLFormat tests that verification URL is built correctly with query parameter
func TestVerifyEmail_URLFormat(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()
	baseURL := "https://api-gateway.com/auth/verify-email"

	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	_, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: baseURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        gofakeit.IPv4Address(),
		},
	})
	require.NoError(t, err)

	// Get token from database
	token, err := st.Storage.GetToken(ctx, email, entity.TokenTypeVerifyEmail)
	require.NoError(t, err)
	require.Len(t, token, 64, "token should be 64 chars (32 bytes hex)")

	// Build expected URL: base URL + ?token=TOKEN
	expectedURL := baseURL + "?token=" + token

	// Parse to verify it's a valid URL
	parsedURL, err := url.Parse(expectedURL)
	require.NoError(t, err)
	require.Equal(t, "https", parsedURL.Scheme)
	require.Equal(t, "api-gateway.com", parsedURL.Host)
	require.Equal(t, "/auth/verify-email", parsedURL.Path)
	require.Equal(t, token, parsedURL.Query().Get("token"))

	// Verify the token works
	_, err = st.AuthService.VerifyEmail(ctx, &authv1.VerifyEmailRequest{
		Token: token,
	})
	require.NoError(t, err)
}
