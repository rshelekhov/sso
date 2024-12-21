package mocks

import (
	"github.com/stretchr/testify/mock"
	"time"
)

type JWTManager struct {
	mock.Mock
}

func (m *JWTManager) NewAccessToken(appID, kid string, additionalClaims map[string]interface{}) (string, error) {
	args := m.Called(appID, kid, additionalClaims)
	return args.String(0), args.Error(1)
}

func (m *JWTManager) NewRefreshToken() string {
	args := m.Called()
	return args.String(0)
}

func (m *JWTManager) Issuer() string {
	args := m.Called()
	return args.String(0)
}

func (m *JWTManager) AccessTokenTTL() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func (m *JWTManager) RefreshTokenTTL() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func (m *JWTManager) Kid(appID string) (string, error) {
	args := m.Called(appID)
	return args.String(0), args.Error(1)
}

func (m *JWTManager) RefreshTokenCookieDomain() string {
	args := m.Called()
	return args.String(0)
}

func (m *JWTManager) RefreshTokenCookiePath() string {
	args := m.Called()
	return args.String(0)
}
