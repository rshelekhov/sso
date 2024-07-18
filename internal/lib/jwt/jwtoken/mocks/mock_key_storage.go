package mocks

import (
	"github.com/rshelekhov/sso/internal/port"
	"github.com/stretchr/testify/mock"
)

type MockKeyStorage struct {
	port.KeyStorage
	mock.Mock
}

func (m *MockKeyStorage) SavePrivateKey(appID string, privateKeyPEM []byte) error {
	args := m.Called(appID, privateKeyPEM)
	return args.Error(0)
}

func (m *MockKeyStorage) GetPrivateKey(appID string) ([]byte, error) {
	args := m.Called(appID)
	return args.Get(0).([]byte), args.Error(1)
}
