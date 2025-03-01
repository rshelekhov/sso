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

// CreateSession provides a mock function with given fields: ctx, _a1
func (_m *Storage) CreateSession(ctx context.Context, _a1 entity.Session) error {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for CreateSession")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.Session) error); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_CreateSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateSession'
type Storage_CreateSession_Call struct {
	*mock.Call
}

// CreateSession is a helper method to define mock.On call
//   - ctx context.Context
//   - _a1 entity.Session
func (_e *Storage_Expecter) CreateSession(ctx interface{}, _a1 interface{}) *Storage_CreateSession_Call {
	return &Storage_CreateSession_Call{Call: _e.mock.On("CreateSession", ctx, _a1)}
}

func (_c *Storage_CreateSession_Call) Run(run func(ctx context.Context, _a1 entity.Session)) *Storage_CreateSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.Session))
	})
	return _c
}

func (_c *Storage_CreateSession_Call) Return(_a0 error) *Storage_CreateSession_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_CreateSession_Call) RunAndReturn(run func(context.Context, entity.Session) error) *Storage_CreateSession_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteAllSessions provides a mock function with given fields: ctx, userID, appID
func (_m *Storage) DeleteAllSessions(ctx context.Context, userID string, appID string) error {
	ret := _m.Called(ctx, userID, appID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteAllSessions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, userID, appID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_DeleteAllSessions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteAllSessions'
type Storage_DeleteAllSessions_Call struct {
	*mock.Call
}

// DeleteAllSessions is a helper method to define mock.On call
//   - ctx context.Context
//   - userID string
//   - appID string
func (_e *Storage_Expecter) DeleteAllSessions(ctx interface{}, userID interface{}, appID interface{}) *Storage_DeleteAllSessions_Call {
	return &Storage_DeleteAllSessions_Call{Call: _e.mock.On("DeleteAllSessions", ctx, userID, appID)}
}

func (_c *Storage_DeleteAllSessions_Call) Run(run func(ctx context.Context, userID string, appID string)) *Storage_DeleteAllSessions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Storage_DeleteAllSessions_Call) Return(_a0 error) *Storage_DeleteAllSessions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_DeleteAllSessions_Call) RunAndReturn(run func(context.Context, string, string) error) *Storage_DeleteAllSessions_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteAllUserDevices provides a mock function with given fields: ctx, userID, appID
func (_m *Storage) DeleteAllUserDevices(ctx context.Context, userID string, appID string) error {
	ret := _m.Called(ctx, userID, appID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteAllUserDevices")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, userID, appID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_DeleteAllUserDevices_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteAllUserDevices'
type Storage_DeleteAllUserDevices_Call struct {
	*mock.Call
}

// DeleteAllUserDevices is a helper method to define mock.On call
//   - ctx context.Context
//   - userID string
//   - appID string
func (_e *Storage_Expecter) DeleteAllUserDevices(ctx interface{}, userID interface{}, appID interface{}) *Storage_DeleteAllUserDevices_Call {
	return &Storage_DeleteAllUserDevices_Call{Call: _e.mock.On("DeleteAllUserDevices", ctx, userID, appID)}
}

func (_c *Storage_DeleteAllUserDevices_Call) Run(run func(ctx context.Context, userID string, appID string)) *Storage_DeleteAllUserDevices_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Storage_DeleteAllUserDevices_Call) Return(_a0 error) *Storage_DeleteAllUserDevices_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_DeleteAllUserDevices_Call) RunAndReturn(run func(context.Context, string, string) error) *Storage_DeleteAllUserDevices_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteRefreshToken provides a mock function with given fields: ctx, refreshToken
func (_m *Storage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	ret := _m.Called(ctx, refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for DeleteRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, refreshToken)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_DeleteRefreshToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteRefreshToken'
type Storage_DeleteRefreshToken_Call struct {
	*mock.Call
}

// DeleteRefreshToken is a helper method to define mock.On call
//   - ctx context.Context
//   - refreshToken string
func (_e *Storage_Expecter) DeleteRefreshToken(ctx interface{}, refreshToken interface{}) *Storage_DeleteRefreshToken_Call {
	return &Storage_DeleteRefreshToken_Call{Call: _e.mock.On("DeleteRefreshToken", ctx, refreshToken)}
}

func (_c *Storage_DeleteRefreshToken_Call) Run(run func(ctx context.Context, refreshToken string)) *Storage_DeleteRefreshToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Storage_DeleteRefreshToken_Call) Return(_a0 error) *Storage_DeleteRefreshToken_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_DeleteRefreshToken_Call) RunAndReturn(run func(context.Context, string) error) *Storage_DeleteRefreshToken_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteSession provides a mock function with given fields: ctx, _a1
func (_m *Storage) DeleteSession(ctx context.Context, _a1 entity.Session) error {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for DeleteSession")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.Session) error); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_DeleteSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteSession'
type Storage_DeleteSession_Call struct {
	*mock.Call
}

// DeleteSession is a helper method to define mock.On call
//   - ctx context.Context
//   - _a1 entity.Session
func (_e *Storage_Expecter) DeleteSession(ctx interface{}, _a1 interface{}) *Storage_DeleteSession_Call {
	return &Storage_DeleteSession_Call{Call: _e.mock.On("DeleteSession", ctx, _a1)}
}

func (_c *Storage_DeleteSession_Call) Run(run func(ctx context.Context, _a1 entity.Session)) *Storage_DeleteSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.Session))
	})
	return _c
}

func (_c *Storage_DeleteSession_Call) Return(_a0 error) *Storage_DeleteSession_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_DeleteSession_Call) RunAndReturn(run func(context.Context, entity.Session) error) *Storage_DeleteSession_Call {
	_c.Call.Return(run)
	return _c
}

// GetSessionByRefreshToken provides a mock function with given fields: ctx, refreshToken
func (_m *Storage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (entity.Session, error) {
	ret := _m.Called(ctx, refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for GetSessionByRefreshToken")
	}

	var r0 entity.Session
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (entity.Session, error)); ok {
		return rf(ctx, refreshToken)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) entity.Session); ok {
		r0 = rf(ctx, refreshToken)
	} else {
		r0 = ret.Get(0).(entity.Session)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, refreshToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetSessionByRefreshToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetSessionByRefreshToken'
type Storage_GetSessionByRefreshToken_Call struct {
	*mock.Call
}

// GetSessionByRefreshToken is a helper method to define mock.On call
//   - ctx context.Context
//   - refreshToken string
func (_e *Storage_Expecter) GetSessionByRefreshToken(ctx interface{}, refreshToken interface{}) *Storage_GetSessionByRefreshToken_Call {
	return &Storage_GetSessionByRefreshToken_Call{Call: _e.mock.On("GetSessionByRefreshToken", ctx, refreshToken)}
}

func (_c *Storage_GetSessionByRefreshToken_Call) Run(run func(ctx context.Context, refreshToken string)) *Storage_GetSessionByRefreshToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Storage_GetSessionByRefreshToken_Call) Return(_a0 entity.Session, _a1 error) *Storage_GetSessionByRefreshToken_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Storage_GetSessionByRefreshToken_Call) RunAndReturn(run func(context.Context, string) (entity.Session, error)) *Storage_GetSessionByRefreshToken_Call {
	_c.Call.Return(run)
	return _c
}

// GetUserDeviceID provides a mock function with given fields: ctx, userID, userAgent
func (_m *Storage) GetUserDeviceID(ctx context.Context, userID string, userAgent string) (string, error) {
	ret := _m.Called(ctx, userID, userAgent)

	if len(ret) == 0 {
		panic("no return value specified for GetUserDeviceID")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (string, error)); ok {
		return rf(ctx, userID, userAgent)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) string); ok {
		r0 = rf(ctx, userID, userAgent)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, userID, userAgent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetUserDeviceID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserDeviceID'
type Storage_GetUserDeviceID_Call struct {
	*mock.Call
}

// GetUserDeviceID is a helper method to define mock.On call
//   - ctx context.Context
//   - userID string
//   - userAgent string
func (_e *Storage_Expecter) GetUserDeviceID(ctx interface{}, userID interface{}, userAgent interface{}) *Storage_GetUserDeviceID_Call {
	return &Storage_GetUserDeviceID_Call{Call: _e.mock.On("GetUserDeviceID", ctx, userID, userAgent)}
}

func (_c *Storage_GetUserDeviceID_Call) Run(run func(ctx context.Context, userID string, userAgent string)) *Storage_GetUserDeviceID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Storage_GetUserDeviceID_Call) Return(_a0 string, _a1 error) *Storage_GetUserDeviceID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Storage_GetUserDeviceID_Call) RunAndReturn(run func(context.Context, string, string) (string, error)) *Storage_GetUserDeviceID_Call {
	_c.Call.Return(run)
	return _c
}

// RegisterDevice provides a mock function with given fields: ctx, device
func (_m *Storage) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	ret := _m.Called(ctx, device)

	if len(ret) == 0 {
		panic("no return value specified for RegisterDevice")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.UserDevice) error); ok {
		r0 = rf(ctx, device)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_RegisterDevice_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RegisterDevice'
type Storage_RegisterDevice_Call struct {
	*mock.Call
}

// RegisterDevice is a helper method to define mock.On call
//   - ctx context.Context
//   - device entity.UserDevice
func (_e *Storage_Expecter) RegisterDevice(ctx interface{}, device interface{}) *Storage_RegisterDevice_Call {
	return &Storage_RegisterDevice_Call{Call: _e.mock.On("RegisterDevice", ctx, device)}
}

func (_c *Storage_RegisterDevice_Call) Run(run func(ctx context.Context, device entity.UserDevice)) *Storage_RegisterDevice_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.UserDevice))
	})
	return _c
}

func (_c *Storage_RegisterDevice_Call) Return(_a0 error) *Storage_RegisterDevice_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_RegisterDevice_Call) RunAndReturn(run func(context.Context, entity.UserDevice) error) *Storage_RegisterDevice_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateLastVisitedAt provides a mock function with given fields: ctx, _a1
func (_m *Storage) UpdateLastVisitedAt(ctx context.Context, _a1 entity.Session) error {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for UpdateLastVisitedAt")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.Session) error); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_UpdateLastVisitedAt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateLastVisitedAt'
type Storage_UpdateLastVisitedAt_Call struct {
	*mock.Call
}

// UpdateLastVisitedAt is a helper method to define mock.On call
//   - ctx context.Context
//   - _a1 entity.Session
func (_e *Storage_Expecter) UpdateLastVisitedAt(ctx interface{}, _a1 interface{}) *Storage_UpdateLastVisitedAt_Call {
	return &Storage_UpdateLastVisitedAt_Call{Call: _e.mock.On("UpdateLastVisitedAt", ctx, _a1)}
}

func (_c *Storage_UpdateLastVisitedAt_Call) Run(run func(ctx context.Context, _a1 entity.Session)) *Storage_UpdateLastVisitedAt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.Session))
	})
	return _c
}

func (_c *Storage_UpdateLastVisitedAt_Call) Return(_a0 error) *Storage_UpdateLastVisitedAt_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_UpdateLastVisitedAt_Call) RunAndReturn(run func(context.Context, entity.Session) error) *Storage_UpdateLastVisitedAt_Call {
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
