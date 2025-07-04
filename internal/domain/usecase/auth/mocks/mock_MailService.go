// Code generated by mockery v2.53.4. DO NOT EDIT.

package mocks

import (
	context "context"

	mail "github.com/rshelekhov/sso/internal/infrastructure/service/mail"
	mock "github.com/stretchr/testify/mock"
)

// MailService is an autogenerated mock type for the MailService type
type MailService struct {
	mock.Mock
}

type MailService_Expecter struct {
	mock *mock.Mock
}

func (_m *MailService) EXPECT() *MailService_Expecter {
	return &MailService_Expecter{mock: &_m.Mock}
}

// SendEmail provides a mock function with given fields: ctx, data
func (_m *MailService) SendEmail(ctx context.Context, data mail.Data) error {
	ret := _m.Called(ctx, data)

	if len(ret) == 0 {
		panic("no return value specified for SendEmail")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, mail.Data) error); ok {
		r0 = rf(ctx, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MailService_SendEmail_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SendEmail'
type MailService_SendEmail_Call struct {
	*mock.Call
}

// SendEmail is a helper method to define mock.On call
//   - ctx context.Context
//   - data mail.Data
func (_e *MailService_Expecter) SendEmail(ctx interface{}, data interface{}) *MailService_SendEmail_Call {
	return &MailService_SendEmail_Call{Call: _e.mock.On("SendEmail", ctx, data)}
}

func (_c *MailService_SendEmail_Call) Run(run func(ctx context.Context, data mail.Data)) *MailService_SendEmail_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(mail.Data))
	})
	return _c
}

func (_c *MailService_SendEmail_Call) Return(_a0 error) *MailService_SendEmail_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MailService_SendEmail_Call) RunAndReturn(run func(context.Context, mail.Data) error) *MailService_SendEmail_Call {
	_c.Call.Return(run)
	return _c
}

// NewMailService creates a new instance of MailService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMailService(t interface {
	mock.TestingT
	Cleanup(func())
}) *MailService {
	mock := &MailService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
