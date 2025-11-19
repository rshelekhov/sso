package api_tests

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/cursor"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/rshelekhov/sso/pkg/jwtauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ptr is a helper function that returns a pointer to the given value
func ptr[T any](v T) *T {
	return &v
}

// mixCase converts a string to alternating upper/lower case
func mixCase(s string) string {
	runes := []rune(s)
	for i := range runes {
		if i%2 == 0 {
			runes[i] = []rune(strings.ToUpper(string(runes[i])))[0]
		} else {
			runes[i] = []rune(strings.ToLower(string(runes[i])))[0]
		}
	}
	return string(runes)
}

func TestSearchUsers_HappyPath_FirstPage(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Use unique test ID to avoid conflicts with parallel tests
	testID := gofakeit.UUID()

	// Create test users with unique test ID
	users := createTestUsersForSearchWithID(t, ctx, st, 5, testID)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search for users with query that matches unique test ID
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    testID,
		PageSize: ptr(int32(10)),
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 5, len(resp.Users), "Should return exactly 5 users")
	assert.Equal(t, int32(5), resp.TotalCount, "Total count should be 5")
	assert.False(t, resp.HasMore, "Should not have more results with page size 10")
	assert.Empty(t, resp.NextPageToken, "Should not have next page token")

	// Verify returned users match the query
	for _, user := range resp.Users {
		assert.Contains(t, user.Email, testID)
	}

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_HappyPath_Pagination(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Use unique test ID to avoid conflicts with parallel tests
	testID := gofakeit.UUID()

	// Create 15 test users with unique test ID
	users := createTestUsersForSearchWithID(t, ctx, st, 15, testID)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// First page
	resp1, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    testID,
		PageSize: ptr(int32(5)),
	})

	require.NoError(t, err)
	require.NotNil(t, resp1)
	assert.Len(t, resp1.Users, 5, "First page should return exactly 5 users")
	assert.Equal(t, int32(15), resp1.TotalCount, "Total count should be 15")
	assert.True(t, resp1.HasMore, "Should have more results")
	assert.NotEmpty(t, resp1.NextPageToken, "Should have next page token")

	// Collect first page user IDs
	page1IDs := make(map[string]bool)
	for _, user := range resp1.Users {
		page1IDs[user.Id] = true
	}

	// Second page using cursor
	resp2, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:     testID,
		PageSize:  ptr(int32(5)),
		PageToken: ptr(resp1.NextPageToken),
	})

	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Len(t, resp2.Users, 5, "Second page should return exactly 5 users")
	assert.Equal(t, resp1.TotalCount, resp2.TotalCount, "Total count should remain same")
	assert.True(t, resp2.HasMore, "Should have more results")
	assert.NotEmpty(t, resp2.NextPageToken, "Should have next page token")

	// Verify no duplicates between pages
	for _, user := range resp2.Users {
		assert.False(t, page1IDs[user.Id], "User %s should not appear in both pages", user.Id)
	}

	// Collect second page user IDs
	page2IDs := make(map[string]bool)
	for _, user := range resp2.Users {
		page2IDs[user.Id] = true
	}

	// Third page (last page)
	resp3, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:     testID,
		PageSize:  ptr(int32(5)),
		PageToken: ptr(resp2.NextPageToken),
	})

	require.NoError(t, err)
	require.NotNil(t, resp3)
	assert.Equal(t, 5, len(resp3.Users), "Third page should return exactly 5 remaining users")
	assert.Equal(t, resp1.TotalCount, resp3.TotalCount, "Total count should remain same")
	assert.False(t, resp3.HasMore, "Should not have more results")
	assert.Empty(t, resp3.NextPageToken, "Should not have next page token")

	// Verify no duplicates with previous pages
	for _, user := range resp3.Users {
		assert.False(t, page1IDs[user.Id], "User %s should not appear in page 1 and page 3", user.Id)
		assert.False(t, page2IDs[user.Id], "User %s should not appear in page 2 and page 3", user.Id)
	}

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_HappyPath_EmptyResults(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Create one user to get token
	users := createTestUsersForSearch(t, ctx, st, 1)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search for non-existent query
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    "nonexistentuserxyz123",
		PageSize: ptr(int32(10)),
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Users, "Should return empty user list")
	assert.Equal(t, int32(0), resp.TotalCount, "Total count should be 0")
	assert.False(t, resp.HasMore, "Should not have more results")
	assert.Empty(t, resp.NextPageToken, "Should not have next page token")

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_HappyPath_CaseInsensitive(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Use unique searchable text for case-insensitive testing
	searchText := "UniqueTest" + gofakeit.UUID()[:8]

	// Create test users with searchText in email
	users := createTestUsersForSearchWithID(t, ctx, st, 3, searchText)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Test different case variations
	testCases := []struct {
		name  string
		query string
	}{
		{"lowercase", strings.ToLower(searchText)},
		{"uppercase", strings.ToUpper(searchText)},
		{"mixedcase", mixCase(searchText)},
	}

	var firstCount int32
	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
				Query:    tc.query,
				PageSize: ptr(int32(10)),
			})

			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, 3, len(resp.Users), "Should return exactly 3 users")
			assert.Equal(t, int32(3), resp.TotalCount, "Total count should be 3")

			if i == 0 {
				firstCount = resp.TotalCount
			} else {
				assert.Equal(t, firstCount, resp.TotalCount, "All case variations should return same count")
			}
		})
	}

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_HappyPath_DefaultPageSize(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Use unique test ID to avoid conflicts with parallel tests
	testID := gofakeit.UUID()

	// Create test users with unique test ID
	users := createTestUsersForSearchWithID(t, ctx, st, 5, testID)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search without specifying page_size (should default to 50)
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query: testID,
		// PageSize: 0, // Default
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 5, len(resp.Users), "Should return exactly 5 users")

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_ValidationError_QueryTooShort(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Create one user to get token
	users := createTestUsersForSearch(t, ctx, st, 1)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search with too short query
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    "ab", // Less than 3 characters
		PageSize: ptr(int32(10)),
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	grpcStatus, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, grpcStatus.Code())
	assert.Contains(t, grpcStatus.Message(), "query must be at least 3 characters")

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_ValidationError_QueryTooLong(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Create one user to get token
	users := createTestUsersForSearch(t, ctx, st, 1)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Create a query longer than 255 characters
	longQuery := ""
	for i := 0; i < 300; i++ {
		longQuery += "a"
	}

	// Search with too long query
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    longQuery,
		PageSize: ptr(int32(10)),
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	grpcStatus, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, grpcStatus.Code())
	assert.Contains(t, grpcStatus.Message(), "query must be at most 255 characters")

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_ValidationError_PageSizeTooLarge(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Create one user to get token
	users := createTestUsersForSearch(t, ctx, st, 1)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search with page_size > 100
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    "test",
		PageSize: ptr(int32(150)), // Exceeds maximum of 100
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	grpcStatus, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, grpcStatus.Code())
	assert.Contains(t, grpcStatus.Message(), "page_size must not exceed 100")

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_ValidationError_InvalidPageToken(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Create one user to get token
	users := createTestUsersForSearch(t, ctx, st, 1)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search with invalid page_token
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:     "test",
		PageSize:  ptr(int32(10)),
		PageToken: ptr("invalid_base64_!!!"),
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	grpcStatus, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, grpcStatus.Code())

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_AuthError_MissingToken(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Add only clientID metadata (no JWT token)
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search without authentication
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    "test",
		PageSize: ptr(int32(10)),
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	grpcStatus, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, grpcStatus.Code())
}

func TestSearchUsers_SpecialCharacters_Escaped(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Create test user with special characters in name
	email := fmt.Sprintf("special%%_chars_%s@example.com", gofakeit.UUID())
	pass := randomFakePassword()
	name := "User%_Test"

	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		Name:            name,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        gofakeit.IPv4Address(),
		},
	})
	require.NoError(t, err)
	token := respReg.GetTokenData()

	// Add auth metadata
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search for literal % character (should be escaped)
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    "User%",
		PageSize: ptr(int32(10)),
	})

	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should find the user with literal % in name
	found := false
	for _, user := range resp.Users {
		if user.Name == name {
			found = true
			break
		}
	}
	assert.True(t, found, "Should find user with special characters")

	// Cleanup
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestSearchUsers_SortOrder(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Use unique test ID to avoid conflicts with parallel tests
	testID := gofakeit.UUID()

	// Create test users with known timestamps
	users := createTestUsersForSearchWithID(t, ctx, st, 5, testID)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Search for users
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:    testID,
		PageSize: ptr(int32(10)),
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 5, len(resp.Users), "Should return exactly 5 users")

	// Verify users are sorted by created_at DESC
	for i := 0; i < len(resp.Users)-1; i++ {
		currentTime := resp.Users[i].UpdatedAt.AsTime()
		nextTime := resp.Users[i+1].UpdatedAt.AsTime()

		assert.True(t, currentTime.After(nextTime) || currentTime.Equal(nextTime),
			"Users should be sorted by created_at DESC, but user[%d] (%v) is before user[%d] (%v)",
			i, currentTime, i+1, nextTime)
	}

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

func TestSearchUsers_CursorValidation_FutureTimestamp(t *testing.T) {
	ctx, st := suite.NewSequential(t)

	// Create one user to get token
	users := createTestUsersForSearch(t, ctx, st, 1)
	token := users[0].Token

	// Add auth metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, token.GetAccessToken())
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Create cursor with future timestamp
	futureCursor := &cursor.SearchCursor{
		CreatedAt: time.Now().Add(2 * time.Hour),
		UserID:    "2bxHvsjfPzGjdS7PGmvnKYXzCPD",
	}

	futureToken, err := cursor.Encode(futureCursor)
	require.NoError(t, err)

	// Search with future timestamp cursor
	resp, err := st.UserService.SearchUsers(ctx, &userv1.SearchUsersRequest{
		Query:     "test",
		PageSize:  ptr(int32(10)),
		PageToken: ptr(futureToken),
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	grpcStatus, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, grpcStatus.Code())

	// Cleanup
	cleanupTestUsers(t, ctx, st, users)
}

// Helper types and functions

type testUserWithToken struct {
	UserID string
	Email  string
	Name   string
	Token  *authv1.TokenData
}

func createTestUsersForSearch(t *testing.T, ctx context.Context, st *suite.Suite, count int) []testUserWithToken {
	t.Helper()

	// Use unique UUID per test to avoid interference with other parallel tests
	uniqueID := gofakeit.UUID()

	users := make([]testUserWithToken, count)

	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	for i := 0; i < count; i++ {
		// Use unique ID to prevent searches from finding other tests' users
		email := fmt.Sprintf("validation-%d-%s@example.com", i, uniqueID)
		pass := randomFakePassword()
		name := fmt.Sprintf("Validation User %d %s", i, uniqueID[:8])

		respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
			Email:           email,
			Password:        pass,
			Name:            name,
			VerificationUrl: cfg.VerificationURL,
			UserDeviceData: &authv1.UserDeviceData{
				UserAgent: gofakeit.UserAgent(),
				Ip:        gofakeit.IPv4Address(),
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, respReg.GetTokenData())

		users[i] = testUserWithToken{
			UserID: respReg.GetUserId(),
			Email:  email,
			Name:   name,
			Token:  respReg.GetTokenData(),
		}

		// Small delay to ensure distinct timestamps
		time.Sleep(10 * time.Millisecond)
	}

	return users
}

func createTestUsersForSearchWithID(t *testing.T, ctx context.Context, st *suite.Suite, count int, testID string) []testUserWithToken {
	t.Helper()

	users := make([]testUserWithToken, count)

	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	for i := 0; i < count; i++ {
		// Use ONLY testID in email to make it searchable and unique per test
		// Don't include "search-test" to avoid interference with other parallel tests
		email := fmt.Sprintf("user-%d-%s@example.com", i, testID)
		pass := randomFakePassword()
		name := fmt.Sprintf("User %d %s", i, testID)

		respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
			Email:           email,
			Password:        pass,
			Name:            name,
			VerificationUrl: cfg.VerificationURL,
			UserDeviceData: &authv1.UserDeviceData{
				UserAgent: gofakeit.UserAgent(),
				Ip:        gofakeit.IPv4Address(),
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, respReg.GetTokenData())

		users[i] = testUserWithToken{
			UserID: respReg.GetUserId(),
			Email:  email,
			Name:   name,
			Token:  respReg.GetTokenData(),
		}

		// Small delay to ensure distinct timestamps
		time.Sleep(10 * time.Millisecond)
	}

	return users
}

func cleanupTestUsers(t *testing.T, ctx context.Context, st *suite.Suite, users []testUserWithToken) {
	t.Helper()

	for _, user := range users {
		params := cleanupParams{
			t:        t,
			st:       st,
			clientID: cfg.ClientID,
			token:    user.Token,
		}
		cleanup(params, cfg.ClientID)
	}
}
