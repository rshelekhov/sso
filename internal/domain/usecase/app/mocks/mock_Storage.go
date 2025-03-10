// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import (
	context "context"

	entity "github.com/rshelekhov/sso/internal/domain/entity"
	mock "github.com/stretchr/testify/mock"
)

// Storage is an autogenerated mock type for the Storage type
type Storage struct {
	mock.Mock
}

type Storage_Expecter struct {
	mock *mock.Mock
}

func (_m *Storage) EXPECT() *Storage_Expecter {
	return &Storage_Expecter{mock: &_m.Mock}
}

// DeleteApp provides a mock function with given fields: ctx, data
func (_m *Storage) DeleteApp(ctx context.Context, data entity.AppData) error {
	ret := _m.Called(ctx, data)

	if len(ret) == 0 {
		panic("no return value specified for DeleteApp")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.AppData) error); ok {
		r0 = rf(ctx, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_DeleteApp_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteApp'
type Storage_DeleteApp_Call struct {
	*mock.Call
}

// DeleteApp is a helper method to define mock.On call
//   - ctx context.Context
//   - data entity.AppData
func (_e *Storage_Expecter) DeleteApp(ctx interface{}, data interface{}) *Storage_DeleteApp_Call {
	return &Storage_DeleteApp_Call{Call: _e.mock.On("DeleteApp", ctx, data)}
}

func (_c *Storage_DeleteApp_Call) Run(run func(ctx context.Context, data entity.AppData)) *Storage_DeleteApp_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.AppData))
	})
	return _c
}

func (_c *Storage_DeleteApp_Call) Return(_a0 error) *Storage_DeleteApp_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_DeleteApp_Call) RunAndReturn(run func(context.Context, entity.AppData) error) *Storage_DeleteApp_Call {
	_c.Call.Return(run)
	return _c
}

// RegisterApp provides a mock function with given fields: ctx, data
func (_m *Storage) RegisterApp(ctx context.Context, data entity.AppData) error {
	ret := _m.Called(ctx, data)

	if len(ret) == 0 {
		panic("no return value specified for RegisterApp")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.AppData) error); ok {
		r0 = rf(ctx, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_RegisterApp_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RegisterApp'
type Storage_RegisterApp_Call struct {
	*mock.Call
}

// RegisterApp is a helper method to define mock.On call
//   - ctx context.Context
//   - data entity.AppData
func (_e *Storage_Expecter) RegisterApp(ctx interface{}, data interface{}) *Storage_RegisterApp_Call {
	return &Storage_RegisterApp_Call{Call: _e.mock.On("RegisterApp", ctx, data)}
}

func (_c *Storage_RegisterApp_Call) Run(run func(ctx context.Context, data entity.AppData)) *Storage_RegisterApp_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.AppData))
	})
	return _c
}

func (_c *Storage_RegisterApp_Call) Return(_a0 error) *Storage_RegisterApp_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_RegisterApp_Call) RunAndReturn(run func(context.Context, entity.AppData) error) *Storage_RegisterApp_Call {
	_c.Call.Return(run)
	return _c
}

// NewStorage creates a new instance of Storage. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStorage(t interface {
	mock.TestingT
	Cleanup(func())
}) *Storage {
	mock := &Storage{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
