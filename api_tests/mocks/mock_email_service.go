package mocks

import (
	"context"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/stretchr/testify/mock"
)

type MockEmailService struct {
	port.MailService
	mock.Mock
}

func NewMockEmailService() *MockEmailService {
	return &MockEmailService{}
}

func (m *MockEmailService) SendMessage(ctx context.Context, subject, body, recipient string) error {
	args := m.Called(ctx, subject, body, recipient)
	return args.Error(0)
}

func (m *MockEmailService) SendHTML(ctx context.Context, subject, html, recipient string) error {
	args := m.Called(ctx, subject, html, recipient)
	return args.Error(0)
}

func (m *MockEmailService) GetTemplatesPath() string {
	args := m.Called()
	return args.String(0)
}
