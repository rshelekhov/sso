// Code generated by mockery v2.53.4. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// TransactionManager is an autogenerated mock type for the TransactionManager type
type TransactionManager struct {
	mock.Mock
}

type TransactionManager_Expecter struct {
	mock *mock.Mock
}

func (_m *TransactionManager) EXPECT() *TransactionManager_Expecter {
	return &TransactionManager_Expecter{mock: &_m.Mock}
}

// WithinTransaction provides a mock function with given fields: ctx, fn
func (_m *TransactionManager) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	ret := _m.Called(ctx, fn)

	if len(ret) == 0 {
		panic("no return value specified for WithinTransaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, func(context.Context) error) error); ok {
		r0 = rf(ctx, fn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TransactionManager_WithinTransaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WithinTransaction'
type TransactionManager_WithinTransaction_Call struct {
	*mock.Call
}

// WithinTransaction is a helper method to define mock.On call
//   - ctx context.Context
//   - fn func(context.Context) error
func (_e *TransactionManager_Expecter) WithinTransaction(ctx interface{}, fn interface{}) *TransactionManager_WithinTransaction_Call {
	return &TransactionManager_WithinTransaction_Call{Call: _e.mock.On("WithinTransaction", ctx, fn)}
}

func (_c *TransactionManager_WithinTransaction_Call) Run(run func(ctx context.Context, fn func(context.Context) error)) *TransactionManager_WithinTransaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(func(context.Context) error))
	})
	return _c
}

func (_c *TransactionManager_WithinTransaction_Call) Return(_a0 error) *TransactionManager_WithinTransaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TransactionManager_WithinTransaction_Call) RunAndReturn(run func(context.Context, func(context.Context) error) error) *TransactionManager_WithinTransaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewTransactionManager creates a new instance of TransactionManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTransactionManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *TransactionManager {
	mock := &TransactionManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
