// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// KeyStorage is an autogenerated mock type for the KeyStorage type
type KeyStorage struct {
	mock.Mock
}

type KeyStorage_Expecter struct {
	mock *mock.Mock
}

func (_m *KeyStorage) EXPECT() *KeyStorage_Expecter {
	return &KeyStorage_Expecter{mock: &_m.Mock}
}

// GetPrivateKey provides a mock function with given fields: appID
func (_m *KeyStorage) GetPrivateKey(appID string) ([]byte, error) {
	ret := _m.Called(appID)

	if len(ret) == 0 {
		panic("no return value specified for GetPrivateKey")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]byte, error)); ok {
		return rf(appID)
	}
	if rf, ok := ret.Get(0).(func(string) []byte); ok {
		r0 = rf(appID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(appID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// KeyStorage_GetPrivateKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetPrivateKey'
type KeyStorage_GetPrivateKey_Call struct {
	*mock.Call
}

// GetPrivateKey is a helper method to define mock.On call
//   - appID string
func (_e *KeyStorage_Expecter) GetPrivateKey(appID interface{}) *KeyStorage_GetPrivateKey_Call {
	return &KeyStorage_GetPrivateKey_Call{Call: _e.mock.On("GetPrivateKey", appID)}
}

func (_c *KeyStorage_GetPrivateKey_Call) Run(run func(appID string)) *KeyStorage_GetPrivateKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *KeyStorage_GetPrivateKey_Call) Return(_a0 []byte, _a1 error) *KeyStorage_GetPrivateKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *KeyStorage_GetPrivateKey_Call) RunAndReturn(run func(string) ([]byte, error)) *KeyStorage_GetPrivateKey_Call {
	_c.Call.Return(run)
	return _c
}

// SavePrivateKey provides a mock function with given fields: appID, privateKeyPEM
func (_m *KeyStorage) SavePrivateKey(appID string, privateKeyPEM []byte) error {
	ret := _m.Called(appID, privateKeyPEM)

	if len(ret) == 0 {
		panic("no return value specified for SavePrivateKey")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, []byte) error); ok {
		r0 = rf(appID, privateKeyPEM)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// KeyStorage_SavePrivateKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SavePrivateKey'
type KeyStorage_SavePrivateKey_Call struct {
	*mock.Call
}

// SavePrivateKey is a helper method to define mock.On call
//   - appID string
//   - privateKeyPEM []byte
func (_e *KeyStorage_Expecter) SavePrivateKey(appID interface{}, privateKeyPEM interface{}) *KeyStorage_SavePrivateKey_Call {
	return &KeyStorage_SavePrivateKey_Call{Call: _e.mock.On("SavePrivateKey", appID, privateKeyPEM)}
}

func (_c *KeyStorage_SavePrivateKey_Call) Run(run func(appID string, privateKeyPEM []byte)) *KeyStorage_SavePrivateKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].([]byte))
	})
	return _c
}

func (_c *KeyStorage_SavePrivateKey_Call) Return(_a0 error) *KeyStorage_SavePrivateKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *KeyStorage_SavePrivateKey_Call) RunAndReturn(run func(string, []byte) error) *KeyStorage_SavePrivateKey_Call {
	_c.Call.Return(run)
	return _c
}

// NewKeyStorage creates a new instance of KeyStorage. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewKeyStorage(t interface {
	mock.TestingT
	Cleanup(func())
}) *KeyStorage {
	mock := &KeyStorage{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
