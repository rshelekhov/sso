package mocks

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/mock"
)

type MockTokenService struct {
	*jwtoken.Service
	mock.Mock
}

func NewMockTokenService() *MockTokenService {
	return &MockTokenService{
		Service: &jwtoken.Service{},
	}
}

func (m *MockTokenService) Algorithm() jwt.SigningMethod {
	args := m.Called()
	return args.Get(0).(jwt.SigningMethod)
}

func (m *MockTokenService) GeneratePrivateKey(appID string) error {
	args := m.Called(appID)
	return args.Error(0)
}

func (m *MockTokenService) GetKeyID(appID string) (string, error) {
	args := m.Called(appID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GetPublicKey(appID string) (interface{}, error) {
	args := m.Called(appID)
	return args.Get(0), args.Error(1)
}

func (m *MockTokenService) NewRefreshToken() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GetUserID(ctx context.Context, appID, key string) (string, error) {
	args := m.Called(ctx, appID, key)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GetClaimsFromToken(ctx context.Context, appID string) (map[string]interface{}, error) {
	args := m.Called(ctx, appID)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockTokenService) GetTokenFromContext(ctx context.Context, appID string) (*jwt.Token, error) {
	args := m.Called(ctx, appID)
	return args.Get(0).(*jwt.Token), args.Error(1)
}

func (m *MockTokenService) ParseToken(tokenString, appID string) (*jwt.Token, error) {
	args := m.Called(tokenString, appID)
	return args.Get(0).(*jwt.Token), args.Error(1)
}
