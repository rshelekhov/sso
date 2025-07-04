// Code generated by mockery v2.53.4. DO NOT EDIT.

package mocks

import (
	context "context"
	time "time"

	mock "github.com/stretchr/testify/mock"
)

// TokenManager is an autogenerated mock type for the TokenManager type
type TokenManager struct {
	mock.Mock
}

type TokenManager_Expecter struct {
	mock *mock.Mock
}

func (_m *TokenManager) EXPECT() *TokenManager_Expecter {
	return &TokenManager_Expecter{mock: &_m.Mock}
}

// ExtractUserIDFromTokenInContext provides a mock function with given fields: ctx, clientID
func (_m *TokenManager) ExtractUserIDFromTokenInContext(ctx context.Context, clientID string) (string, error) {
	ret := _m.Called(ctx, clientID)

	if len(ret) == 0 {
		panic("no return value specified for ExtractUserIDFromTokenInContext")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, clientID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, clientID)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, clientID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TokenManager_ExtractUserIDFromTokenInContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExtractUserIDFromTokenInContext'
type TokenManager_ExtractUserIDFromTokenInContext_Call struct {
	*mock.Call
}

// ExtractUserIDFromTokenInContext is a helper method to define mock.On call
//   - ctx context.Context
//   - clientID string
func (_e *TokenManager_Expecter) ExtractUserIDFromTokenInContext(ctx interface{}, clientID interface{}) *TokenManager_ExtractUserIDFromTokenInContext_Call {
	return &TokenManager_ExtractUserIDFromTokenInContext_Call{Call: _e.mock.On("ExtractUserIDFromTokenInContext", ctx, clientID)}
}

func (_c *TokenManager_ExtractUserIDFromTokenInContext_Call) Run(run func(ctx context.Context, clientID string)) *TokenManager_ExtractUserIDFromTokenInContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *TokenManager_ExtractUserIDFromTokenInContext_Call) Return(_a0 string, _a1 error) *TokenManager_ExtractUserIDFromTokenInContext_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *TokenManager_ExtractUserIDFromTokenInContext_Call) RunAndReturn(run func(context.Context, string) (string, error)) *TokenManager_ExtractUserIDFromTokenInContext_Call {
	_c.Call.Return(run)
	return _c
}

// HashPassword provides a mock function with given fields: password
func (_m *TokenManager) HashPassword(password string) (string, error) {
	ret := _m.Called(password)

	if len(ret) == 0 {
		panic("no return value specified for HashPassword")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(password)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(password)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(password)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TokenManager_HashPassword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HashPassword'
type TokenManager_HashPassword_Call struct {
	*mock.Call
}

// HashPassword is a helper method to define mock.On call
//   - password string
func (_e *TokenManager_Expecter) HashPassword(password interface{}) *TokenManager_HashPassword_Call {
	return &TokenManager_HashPassword_Call{Call: _e.mock.On("HashPassword", password)}
}

func (_c *TokenManager_HashPassword_Call) Run(run func(password string)) *TokenManager_HashPassword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *TokenManager_HashPassword_Call) Return(_a0 string, _a1 error) *TokenManager_HashPassword_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *TokenManager_HashPassword_Call) RunAndReturn(run func(string) (string, error)) *TokenManager_HashPassword_Call {
	_c.Call.Return(run)
	return _c
}

// JWKSTTL provides a mock function with no fields
func (_m *TokenManager) JWKSTTL() time.Duration {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for JWKSTTL")
	}

	var r0 time.Duration
	if rf, ok := ret.Get(0).(func() time.Duration); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	return r0
}

// TokenManager_JWKSTTL_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'JWKSTTL'
type TokenManager_JWKSTTL_Call struct {
	*mock.Call
}

// JWKSTTL is a helper method to define mock.On call
func (_e *TokenManager_Expecter) JWKSTTL() *TokenManager_JWKSTTL_Call {
	return &TokenManager_JWKSTTL_Call{Call: _e.mock.On("JWKSTTL")}
}

func (_c *TokenManager_JWKSTTL_Call) Run(run func()) *TokenManager_JWKSTTL_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *TokenManager_JWKSTTL_Call) Return(_a0 time.Duration) *TokenManager_JWKSTTL_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TokenManager_JWKSTTL_Call) RunAndReturn(run func() time.Duration) *TokenManager_JWKSTTL_Call {
	_c.Call.Return(run)
	return _c
}

// Kid provides a mock function with given fields: clientID
func (_m *TokenManager) Kid(clientID string) (string, error) {
	ret := _m.Called(clientID)

	if len(ret) == 0 {
		panic("no return value specified for Kid")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(clientID)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(clientID)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(clientID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TokenManager_Kid_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Kid'
type TokenManager_Kid_Call struct {
	*mock.Call
}

// Kid is a helper method to define mock.On call
//   - clientID string
func (_e *TokenManager_Expecter) Kid(clientID interface{}) *TokenManager_Kid_Call {
	return &TokenManager_Kid_Call{Call: _e.mock.On("Kid", clientID)}
}

func (_c *TokenManager_Kid_Call) Run(run func(clientID string)) *TokenManager_Kid_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *TokenManager_Kid_Call) Return(_a0 string, _a1 error) *TokenManager_Kid_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *TokenManager_Kid_Call) RunAndReturn(run func(string) (string, error)) *TokenManager_Kid_Call {
	_c.Call.Return(run)
	return _c
}

// PasswordMatch provides a mock function with given fields: hash, password
func (_m *TokenManager) PasswordMatch(hash string, password string) (bool, error) {
	ret := _m.Called(hash, password)

	if len(ret) == 0 {
		panic("no return value specified for PasswordMatch")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string) (bool, error)); ok {
		return rf(hash, password)
	}
	if rf, ok := ret.Get(0).(func(string, string) bool); ok {
		r0 = rf(hash, password)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(hash, password)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TokenManager_PasswordMatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'PasswordMatch'
type TokenManager_PasswordMatch_Call struct {
	*mock.Call
}

// PasswordMatch is a helper method to define mock.On call
//   - hash string
//   - password string
func (_e *TokenManager_Expecter) PasswordMatch(hash interface{}, password interface{}) *TokenManager_PasswordMatch_Call {
	return &TokenManager_PasswordMatch_Call{Call: _e.mock.On("PasswordMatch", hash, password)}
}

func (_c *TokenManager_PasswordMatch_Call) Run(run func(hash string, password string)) *TokenManager_PasswordMatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *TokenManager_PasswordMatch_Call) Return(_a0 bool, _a1 error) *TokenManager_PasswordMatch_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *TokenManager_PasswordMatch_Call) RunAndReturn(run func(string, string) (bool, error)) *TokenManager_PasswordMatch_Call {
	_c.Call.Return(run)
	return _c
}

// PublicKey provides a mock function with given fields: clientID
func (_m *TokenManager) PublicKey(clientID string) (interface{}, error) {
	ret := _m.Called(clientID)

	if len(ret) == 0 {
		panic("no return value specified for PublicKey")
	}

	var r0 interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (interface{}, error)); ok {
		return rf(clientID)
	}
	if rf, ok := ret.Get(0).(func(string) interface{}); ok {
		r0 = rf(clientID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(clientID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TokenManager_PublicKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'PublicKey'
type TokenManager_PublicKey_Call struct {
	*mock.Call
}

// PublicKey is a helper method to define mock.On call
//   - clientID string
func (_e *TokenManager_Expecter) PublicKey(clientID interface{}) *TokenManager_PublicKey_Call {
	return &TokenManager_PublicKey_Call{Call: _e.mock.On("PublicKey", clientID)}
}

func (_c *TokenManager_PublicKey_Call) Run(run func(clientID string)) *TokenManager_PublicKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *TokenManager_PublicKey_Call) Return(_a0 interface{}, _a1 error) *TokenManager_PublicKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *TokenManager_PublicKey_Call) RunAndReturn(run func(string) (interface{}, error)) *TokenManager_PublicKey_Call {
	_c.Call.Return(run)
	return _c
}

// SigningMethod provides a mock function with no fields
func (_m *TokenManager) SigningMethod() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for SigningMethod")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// TokenManager_SigningMethod_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SigningMethod'
type TokenManager_SigningMethod_Call struct {
	*mock.Call
}

// SigningMethod is a helper method to define mock.On call
func (_e *TokenManager_Expecter) SigningMethod() *TokenManager_SigningMethod_Call {
	return &TokenManager_SigningMethod_Call{Call: _e.mock.On("SigningMethod")}
}

func (_c *TokenManager_SigningMethod_Call) Run(run func()) *TokenManager_SigningMethod_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *TokenManager_SigningMethod_Call) Return(_a0 string) *TokenManager_SigningMethod_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *TokenManager_SigningMethod_Call) RunAndReturn(run func() string) *TokenManager_SigningMethod_Call {
	_c.Call.Return(run)
	return _c
}

// NewTokenManager creates a new instance of TokenManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTokenManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *TokenManager {
	mock := &TokenManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
