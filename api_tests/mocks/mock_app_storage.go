package mocks

import (
	"context"

	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/stretchr/testify/mock"
)

type MockAppStorage struct {
	port.AppStorage
	mock.Mock
}

func NewMockAppStorage() *MockAppStorage {
	return &MockAppStorage{}
}

func (m *MockAppStorage) RegisterApp(ctx context.Context, data model.AppData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockAppStorage) DeleteApp(ctx context.Context, data model.AppData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}
