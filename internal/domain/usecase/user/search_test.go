package user_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	"github.com/rshelekhov/sso/internal/domain/usecase/user/mocks"
	"github.com/rshelekhov/sso/internal/lib/logger/slogdiscard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUserUsecase_SearchUsers(t *testing.T) {
	ctx := mock.MatchedBy(func(context.Context) bool { return true })
	clientID := "test-app-id"
	query := "john"
	now := time.Now()

	// Create test users with different timestamps for pagination
	testUsers := []entity.User{
		{
			ID:        "user_id_1",
			Email:     "john.doe@example.com",
			Name:      "John Doe",
			Verified:  true,
			CreatedAt: now.Add(-10 * time.Hour),
			UpdatedAt: now,
		},
		{
			ID:        "user_id_2",
			Email:     "jane.smith@example.com",
			Name:      "Jane Smith",
			Verified:  false,
			CreatedAt: now.Add(-20 * time.Hour),
			UpdatedAt: now,
		},
		{
			ID:        "user_id_3",
			Email:     "john.smith@example.com",
			Name:      "John Smith",
			Verified:  true,
			CreatedAt: now.Add(-30 * time.Hour),
			UpdatedAt: now,
		},
	}

	tests := []struct {
		name                 string
		query                string
		pageSize             int32
		cursorCreatedAt      *time.Time
		cursorID             *string
		mockBehavior         func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder)
		expectedUsersCount   int
		expectedTotalCount   int32
		expectedHasMore      bool
		expectedLastCreatedAt bool
		expectedLastID       bool
		expectedError        error
	}{
		{
			name:            "Success - First page with results and has more",
			query:           query,
			pageSize:        2,
			cursorCreatedAt: nil,
			cursorID:        nil,
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				// Expect pageSize+1 results
				userMgr.EXPECT().SearchUsers(ctx, "john", int32(3), (*time.Time)(nil), (*string)(nil)).
					Once().
					Return(testUsers, nil)

				userMgr.EXPECT().CountSearchUsers(ctx, "john").
					Once().
					Return(int32(10), nil)

				metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
				metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 2).Once()
			},
			expectedUsersCount:   2,
			expectedTotalCount:   10,
			expectedHasMore:      true,
			expectedLastCreatedAt: true,
			expectedLastID:       true,
			expectedError:        nil,
		},
		{
			name:            "Success - Last page without more results",
			query:           query,
			pageSize:        10,
			cursorCreatedAt: nil,
			cursorID:        nil,
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				// Return fewer than pageSize+1
				userMgr.EXPECT().SearchUsers(ctx, "john", int32(11), (*time.Time)(nil), (*string)(nil)).
					Once().
					Return(testUsers, nil)

				userMgr.EXPECT().CountSearchUsers(ctx, "john").
					Once().
					Return(int32(3), nil)

				metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
				metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 3).Once()
			},
			expectedUsersCount:   3,
			expectedTotalCount:   3,
			expectedHasMore:      false,
			expectedLastCreatedAt: false,
			expectedLastID:       false,
			expectedError:        nil,
		},
		{
			name:            "Success - Empty results",
			query:           "nonexistent",
			pageSize:        50,
			cursorCreatedAt: nil,
			cursorID:        nil,
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				userMgr.EXPECT().SearchUsers(ctx, "nonexistent", int32(51), (*time.Time)(nil), (*string)(nil)).
					Once().
					Return([]entity.User{}, nil)

				userMgr.EXPECT().CountSearchUsers(ctx, "nonexistent").
					Once().
					Return(int32(0), nil)

				metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
				metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 0).Once()
			},
			expectedUsersCount:   0,
			expectedTotalCount:   0,
			expectedHasMore:      false,
			expectedLastCreatedAt: false,
			expectedLastID:       false,
			expectedError:        nil,
		},
		{
			name:     "Success - With cursor (paginated)",
			query:    query,
			pageSize: 2,
			cursorCreatedAt: func() *time.Time {
				t := testUsers[0].CreatedAt
				return &t
			}(),
			cursorID: func() *string {
				id := testUsers[0].ID
				return &id
			}(),
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				cursorTime := testUsers[0].CreatedAt
				cursorIDVal := testUsers[0].ID

				userMgr.EXPECT().SearchUsers(ctx, "john", int32(3), &cursorTime, &cursorIDVal).
					Once().
					Return(testUsers[1:], nil)

				userMgr.EXPECT().CountSearchUsers(ctx, "john").
					Once().
					Return(int32(10), nil)

				metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
				metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 2).Once()
			},
			expectedUsersCount:   2,
			expectedTotalCount:   10,
			expectedHasMore:      false,
			expectedLastCreatedAt: false,
			expectedLastID:       false,
			expectedError:        nil,
		},
		{
			name:            "Success - Page size default (0 becomes 50)",
			query:           query,
			pageSize:        0,
			cursorCreatedAt: nil,
			cursorID:        nil,
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				// Should use default 50
				userMgr.EXPECT().SearchUsers(ctx, "john", int32(51), (*time.Time)(nil), (*string)(nil)).
					Once().
					Return(testUsers, nil)

				userMgr.EXPECT().CountSearchUsers(ctx, "john").
					Once().
					Return(int32(3), nil)

				metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
				metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 3).Once()
			},
			expectedUsersCount:   3,
			expectedTotalCount:   3,
			expectedHasMore:      false,
			expectedLastCreatedAt: false,
			expectedLastID:       false,
			expectedError:        nil,
		},
		{
			name:            "Success - Page size enforced maximum (150 becomes 100)",
			query:           query,
			pageSize:        150,
			cursorCreatedAt: nil,
			cursorID:        nil,
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				// Should be capped at 100
				userMgr.EXPECT().SearchUsers(ctx, "john", int32(101), (*time.Time)(nil), (*string)(nil)).
					Once().
					Return(testUsers, nil)

				userMgr.EXPECT().CountSearchUsers(ctx, "john").
					Once().
					Return(int32(3), nil)

				metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
				metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 3).Once()
			},
			expectedUsersCount:   3,
			expectedTotalCount:   3,
			expectedHasMore:      false,
			expectedLastCreatedAt: false,
			expectedLastID:       false,
			expectedError:        nil,
		},
		{
			name:            "Error - Failed to search users",
			query:           query,
			pageSize:        10,
			cursorCreatedAt: nil,
			cursorID:        nil,
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				userMgr.EXPECT().SearchUsers(ctx, "john", int32(11), (*time.Time)(nil), (*string)(nil)).
					Once().
					Return(nil, errors.New("database connection lost"))
			},
			expectedUsersCount:   0,
			expectedTotalCount:   0,
			expectedHasMore:      false,
			expectedLastCreatedAt: false,
			expectedLastID:       false,
			expectedError:        domain.ErrFailedToSearchUsers,
		},
		{
			name:            "Error - Failed to count users",
			query:           query,
			pageSize:        10,
			cursorCreatedAt: nil,
			cursorID:        nil,
			mockBehavior: func(userMgr *mocks.UserdataManager, metricsMgr *mocks.MetricsRecorder) {
				userMgr.EXPECT().SearchUsers(ctx, "john", int32(11), (*time.Time)(nil), (*string)(nil)).
					Once().
					Return(testUsers, nil)

				userMgr.EXPECT().CountSearchUsers(ctx, "john").
					Once().
					Return(int32(0), errors.New("count query failed"))
			},
			expectedUsersCount:   0,
			expectedTotalCount:   0,
			expectedHasMore:      false,
			expectedLastCreatedAt: false,
			expectedLastID:       false,
			expectedError:        domain.ErrFailedToCountSearchUsers,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMgr := mocks.NewUserdataManager(t)
			metricsMgr := mocks.NewMetricsRecorder(t)

			tt.mockBehavior(userMgr, metricsMgr)

			log := slogdiscard.NewDiscardLogger()

			userUsecase := user.NewUsecase(log, nil, nil, userMgr, nil, nil, nil, nil, metricsMgr)

			users, totalCount, lastCreatedAt, lastID, hasMore, err := userUsecase.SearchUsers(
				context.Background(),
				clientID,
				tt.query,
				tt.pageSize,
				tt.cursorCreatedAt,
				tt.cursorID,
			)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				return
			}

			require.NoError(t, err)
			assert.Len(t, users, tt.expectedUsersCount)
			assert.Equal(t, tt.expectedTotalCount, totalCount)
			assert.Equal(t, tt.expectedHasMore, hasMore)

			if tt.expectedLastCreatedAt {
				require.NotNil(t, lastCreatedAt)
				assert.Equal(t, users[len(users)-1].CreatedAt, *lastCreatedAt)
			} else {
				assert.Nil(t, lastCreatedAt)
			}

			if tt.expectedLastID {
				require.NotNil(t, lastID)
				assert.Equal(t, users[len(users)-1].ID, *lastID)
			} else {
				assert.Nil(t, lastID)
			}
		})
	}
}

func TestSanitizeSearchQuery(t *testing.T) {
	// This tests the sanitization function indirectly through SearchUsers
	ctx := mock.MatchedBy(func(context.Context) bool { return true })
	clientID := "test-app-id"

	tests := []struct {
		name           string
		inputQuery     string
		expectedSanitized string
	}{
		{
			name:           "No special characters",
			inputQuery:     "john",
			expectedSanitized: "john",
		},
		{
			name:           "Query with % wildcard",
			inputQuery:     "user%",
			expectedSanitized: "user\\%",
		},
		{
			name:           "Query with _ wildcard",
			inputQuery:     "user_test",
			expectedSanitized: "user\\_test",
		},
		{
			name:           "Query with both wildcards",
			inputQuery:     "%user_test%",
			expectedSanitized: "\\%user\\_test\\%",
		},
		{
			name:           "Multiple occurrences",
			inputQuery:     "%%__%%",
			expectedSanitized: "\\%\\%\\_\\_\\%\\%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMgr := mocks.NewUserdataManager(t)
			metricsMgr := mocks.NewMetricsRecorder(t)

			// The mock should receive the sanitized query
			userMgr.EXPECT().SearchUsers(ctx, tt.expectedSanitized, int32(51), (*time.Time)(nil), (*string)(nil)).
				Once().
				Return([]entity.User{}, nil)

			userMgr.EXPECT().CountSearchUsers(ctx, tt.expectedSanitized).
				Once().
				Return(int32(0), nil)

			metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
			metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 0).Once()

			log := slogdiscard.NewDiscardLogger()

			userUsecase := user.NewUsecase(log, nil, nil, userMgr, nil, nil, nil, nil, metricsMgr)

			_, _, _, _, _, err := userUsecase.SearchUsers(
				context.Background(),
				clientID,
				tt.inputQuery,
				0,
				nil,
				nil,
			)

			require.NoError(t, err)
		})
	}
}

func TestUserUsecase_SearchUsers_PaginationBoundary(t *testing.T) {
	// Test that pagination boundaries are calculated correctly
	ctx := mock.MatchedBy(func(context.Context) bool { return true })
	clientID := "test-app-id"
	query := "test"
	now := time.Now()

	// Create exactly pageSize + 1 users
	users := make([]entity.User, 11)
	for i := 0; i < 11; i++ {
		users[i] = entity.User{
			ID:        fmt.Sprintf("user_id_%d", i),
			Email:     fmt.Sprintf("user%d@example.com", i),
			Name:      fmt.Sprintf("Test User %d", i),
			Verified:  true,
			CreatedAt: now.Add(-time.Hour * time.Duration(i)),
			UpdatedAt: now,
		}
	}

	userMgr := mocks.NewUserdataManager(t)
	metricsMgr := mocks.NewMetricsRecorder(t)

	// Mock returns pageSize+1 results
	userMgr.EXPECT().SearchUsers(ctx, "test", int32(11), (*time.Time)(nil), (*string)(nil)).
		Once().
		Return(users, nil)

	userMgr.EXPECT().CountSearchUsers(ctx, "test").
		Once().
		Return(int32(20), nil)

	metricsMgr.EXPECT().RecordUserSearchRequest(ctx, clientID).Once()
	metricsMgr.EXPECT().RecordUserSearchResults(ctx, clientID, 10).Once()

	log := slogdiscard.NewDiscardLogger()
	userUsecase := user.NewUsecase(log, nil, nil, userMgr, nil, nil, nil, nil, metricsMgr)

	resultUsers, totalCount, lastCreatedAt, lastID, hasMore, err := userUsecase.SearchUsers(
		context.Background(),
		clientID,
		query,
		10, // pageSize
		nil,
		nil,
	)

	require.NoError(t, err)
	assert.Len(t, resultUsers, 10, "Should return exactly pageSize results")
	assert.Equal(t, int32(20), totalCount)
	assert.True(t, hasMore, "Should indicate more results available")
	require.NotNil(t, lastCreatedAt)
	require.NotNil(t, lastID)

	// Last returned user should be the 10th user (index 9)
	assert.Equal(t, users[9].CreatedAt, *lastCreatedAt)
	assert.Equal(t, users[9].ID, *lastID)
}
