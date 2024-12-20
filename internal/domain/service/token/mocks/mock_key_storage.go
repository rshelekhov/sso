package mocks

import "github.com/stretchr/testify/mock"

type KeyStorage struct {
	mock.Mock
}

func (m *KeyStorage) SavePrivateKey(appID string, privateKeyPEM []byte) error {
	args := m.Called(appID, privateKeyPEM)
	return args.Error(0)
}

func (m *KeyStorage) GetPrivateKey(appID string) ([]byte, error) {
	args := m.Called(appID)
	return args.Get(0).([]byte), args.Error(1)
}
