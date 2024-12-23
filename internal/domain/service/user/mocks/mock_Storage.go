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

// DeleteAllTokens provides a mock function with given fields: ctx, appID, userID
func (_m *Storage) DeleteAllTokens(ctx context.Context, appID string, userID string) error {
	ret := _m.Called(ctx, appID, userID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteAllTokens")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, appID, userID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_DeleteAllTokens_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteAllTokens'
type Storage_DeleteAllTokens_Call struct {
	*mock.Call
}

// DeleteAllTokens is a helper method to define mock.On call
//   - ctx context.Context
//   - appID string
//   - userID string
func (_e *Storage_Expecter) DeleteAllTokens(ctx interface{}, appID interface{}, userID interface{}) *Storage_DeleteAllTokens_Call {
	return &Storage_DeleteAllTokens_Call{Call: _e.mock.On("DeleteAllTokens", ctx, appID, userID)}
}

func (_c *Storage_DeleteAllTokens_Call) Run(run func(ctx context.Context, appID string, userID string)) *Storage_DeleteAllTokens_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Storage_DeleteAllTokens_Call) Return(_a0 error) *Storage_DeleteAllTokens_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_DeleteAllTokens_Call) RunAndReturn(run func(context.Context, string, string) error) *Storage_DeleteAllTokens_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteUser provides a mock function with given fields: ctx, _a1
func (_m *Storage) DeleteUser(ctx context.Context, _a1 entity.User) error {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.User) error); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_DeleteUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteUser'
type Storage_DeleteUser_Call struct {
	*mock.Call
}

// DeleteUser is a helper method to define mock.On call
//   - ctx context.Context
//   - _a1 entity.User
func (_e *Storage_Expecter) DeleteUser(ctx interface{}, _a1 interface{}) *Storage_DeleteUser_Call {
	return &Storage_DeleteUser_Call{Call: _e.mock.On("DeleteUser", ctx, _a1)}
}

func (_c *Storage_DeleteUser_Call) Run(run func(ctx context.Context, _a1 entity.User)) *Storage_DeleteUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.User))
	})
	return _c
}

func (_c *Storage_DeleteUser_Call) Return(_a0 error) *Storage_DeleteUser_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_DeleteUser_Call) RunAndReturn(run func(context.Context, entity.User) error) *Storage_DeleteUser_Call {
	_c.Call.Return(run)
	return _c
}

// GetUserByEmail provides a mock function with given fields: ctx, appID, email
func (_m *Storage) GetUserByEmail(ctx context.Context, appID string, email string) (entity.User, error) {
	ret := _m.Called(ctx, appID, email)

	if len(ret) == 0 {
		panic("no return value specified for GetUserByEmail")
	}

	var r0 entity.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (entity.User, error)); ok {
		return rf(ctx, appID, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) entity.User); ok {
		r0 = rf(ctx, appID, email)
	} else {
		r0 = ret.Get(0).(entity.User)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, appID, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetUserByEmail_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserByEmail'
type Storage_GetUserByEmail_Call struct {
	*mock.Call
}

// GetUserByEmail is a helper method to define mock.On call
//   - ctx context.Context
//   - appID string
//   - email string
func (_e *Storage_Expecter) GetUserByEmail(ctx interface{}, appID interface{}, email interface{}) *Storage_GetUserByEmail_Call {
	return &Storage_GetUserByEmail_Call{Call: _e.mock.On("GetUserByEmail", ctx, appID, email)}
}

func (_c *Storage_GetUserByEmail_Call) Run(run func(ctx context.Context, appID string, email string)) *Storage_GetUserByEmail_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Storage_GetUserByEmail_Call) Return(_a0 entity.User, _a1 error) *Storage_GetUserByEmail_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Storage_GetUserByEmail_Call) RunAndReturn(run func(context.Context, string, string) (entity.User, error)) *Storage_GetUserByEmail_Call {
	_c.Call.Return(run)
	return _c
}

// GetUserByID provides a mock function with given fields: ctx, appID, userID
func (_m *Storage) GetUserByID(ctx context.Context, appID string, userID string) (entity.User, error) {
	ret := _m.Called(ctx, appID, userID)

	if len(ret) == 0 {
		panic("no return value specified for GetUserByID")
	}

	var r0 entity.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (entity.User, error)); ok {
		return rf(ctx, appID, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) entity.User); ok {
		r0 = rf(ctx, appID, userID)
	} else {
		r0 = ret.Get(0).(entity.User)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, appID, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetUserByID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserByID'
type Storage_GetUserByID_Call struct {
	*mock.Call
}

// GetUserByID is a helper method to define mock.On call
//   - ctx context.Context
//   - appID string
//   - userID string
func (_e *Storage_Expecter) GetUserByID(ctx interface{}, appID interface{}, userID interface{}) *Storage_GetUserByID_Call {
	return &Storage_GetUserByID_Call{Call: _e.mock.On("GetUserByID", ctx, appID, userID)}
}

func (_c *Storage_GetUserByID_Call) Run(run func(ctx context.Context, appID string, userID string)) *Storage_GetUserByID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Storage_GetUserByID_Call) Return(_a0 entity.User, _a1 error) *Storage_GetUserByID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Storage_GetUserByID_Call) RunAndReturn(run func(context.Context, string, string) (entity.User, error)) *Storage_GetUserByID_Call {
	_c.Call.Return(run)
	return _c
}

// GetUserData provides a mock function with given fields: ctx, appID, userID
func (_m *Storage) GetUserData(ctx context.Context, appID string, userID string) (entity.User, error) {
	ret := _m.Called(ctx, appID, userID)

	if len(ret) == 0 {
		panic("no return value specified for GetUserData")
	}

	var r0 entity.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (entity.User, error)); ok {
		return rf(ctx, appID, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) entity.User); ok {
		r0 = rf(ctx, appID, userID)
	} else {
		r0 = ret.Get(0).(entity.User)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, appID, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetUserData_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserData'
type Storage_GetUserData_Call struct {
	*mock.Call
}

// GetUserData is a helper method to define mock.On call
//   - ctx context.Context
//   - appID string
//   - userID string
func (_e *Storage_Expecter) GetUserData(ctx interface{}, appID interface{}, userID interface{}) *Storage_GetUserData_Call {
	return &Storage_GetUserData_Call{Call: _e.mock.On("GetUserData", ctx, appID, userID)}
}

func (_c *Storage_GetUserData_Call) Run(run func(ctx context.Context, appID string, userID string)) *Storage_GetUserData_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Storage_GetUserData_Call) Return(_a0 entity.User, _a1 error) *Storage_GetUserData_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Storage_GetUserData_Call) RunAndReturn(run func(context.Context, string, string) (entity.User, error)) *Storage_GetUserData_Call {
	_c.Call.Return(run)
	return _c
}

// GetUserStatusByEmail provides a mock function with given fields: ctx, email
func (_m *Storage) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for GetUserStatusByEmail")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetUserStatusByEmail_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserStatusByEmail'
type Storage_GetUserStatusByEmail_Call struct {
	*mock.Call
}

// GetUserStatusByEmail is a helper method to define mock.On call
//   - ctx context.Context
//   - email string
func (_e *Storage_Expecter) GetUserStatusByEmail(ctx interface{}, email interface{}) *Storage_GetUserStatusByEmail_Call {
	return &Storage_GetUserStatusByEmail_Call{Call: _e.mock.On("GetUserStatusByEmail", ctx, email)}
}

func (_c *Storage_GetUserStatusByEmail_Call) Run(run func(ctx context.Context, email string)) *Storage_GetUserStatusByEmail_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Storage_GetUserStatusByEmail_Call) Return(_a0 string, _a1 error) *Storage_GetUserStatusByEmail_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Storage_GetUserStatusByEmail_Call) RunAndReturn(run func(context.Context, string) (string, error)) *Storage_GetUserStatusByEmail_Call {
	_c.Call.Return(run)
	return _c
}

// GetUserStatusByID provides a mock function with given fields: ctx, userID
func (_m *Storage) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	ret := _m.Called(ctx, userID)

	if len(ret) == 0 {
		panic("no return value specified for GetUserStatusByID")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, userID)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Storage_GetUserStatusByID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserStatusByID'
type Storage_GetUserStatusByID_Call struct {
	*mock.Call
}

// GetUserStatusByID is a helper method to define mock.On call
//   - ctx context.Context
//   - userID string
func (_e *Storage_Expecter) GetUserStatusByID(ctx interface{}, userID interface{}) *Storage_GetUserStatusByID_Call {
	return &Storage_GetUserStatusByID_Call{Call: _e.mock.On("GetUserStatusByID", ctx, userID)}
}

func (_c *Storage_GetUserStatusByID_Call) Run(run func(ctx context.Context, userID string)) *Storage_GetUserStatusByID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *Storage_GetUserStatusByID_Call) Return(_a0 string, _a1 error) *Storage_GetUserStatusByID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Storage_GetUserStatusByID_Call) RunAndReturn(run func(context.Context, string) (string, error)) *Storage_GetUserStatusByID_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateUser provides a mock function with given fields: ctx, _a1
func (_m *Storage) UpdateUser(ctx context.Context, _a1 entity.User) error {
	ret := _m.Called(ctx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for UpdateUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.User) error); ok {
		r0 = rf(ctx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Storage_UpdateUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateUser'
type Storage_UpdateUser_Call struct {
	*mock.Call
}

// UpdateUser is a helper method to define mock.On call
//   - ctx context.Context
//   - _a1 entity.User
func (_e *Storage_Expecter) UpdateUser(ctx interface{}, _a1 interface{}) *Storage_UpdateUser_Call {
	return &Storage_UpdateUser_Call{Call: _e.mock.On("UpdateUser", ctx, _a1)}
}

func (_c *Storage_UpdateUser_Call) Run(run func(ctx context.Context, _a1 entity.User)) *Storage_UpdateUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.User))
	})
	return _c
}

func (_c *Storage_UpdateUser_Call) Return(_a0 error) *Storage_UpdateUser_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Storage_UpdateUser_Call) RunAndReturn(run func(context.Context, entity.User) error) *Storage_UpdateUser_Call {
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
