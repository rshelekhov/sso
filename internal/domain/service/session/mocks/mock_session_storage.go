package mocks

import (
	"context"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/stretchr/testify/mock"
)

type SessionStorage struct {
	mock.Mock
}

func (m *SessionStorage) CreateUserSession(ctx context.Context, session entity.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *SessionStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(entity.Session), args.Error(1)
}

func (m *SessionStorage) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *SessionStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func (m *SessionStorage) DeleteSession(ctx context.Context, session entity.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *SessionStorage) DeleteAllSessions(ctx context.Context, userID, appID string) error {
	args := m.Called(ctx, userID, appID)
	return args.Error(0)
}

func (m *SessionStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	args := m.Called(ctx, userID, userAgent)
	return args.String(0), args.Error(1)
}

func (m *SessionStorage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}
