// Code generated by MockGen. DO NOT EDIT.
// Source: ./tokenAuthenticator.go

// Package user is a generated GoMock package.
package user

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockTokenAuthenticator is a mock of TokenAuthenticator interface.
type MockTokenAuthenticator struct {
	ctrl     *gomock.Controller
	recorder *MockTokenAuthenticatorMockRecorder
}

// MockTokenAuthenticatorMockRecorder is the mock recorder for MockTokenAuthenticator.
type MockTokenAuthenticatorMockRecorder struct {
	mock *MockTokenAuthenticator
}

// NewMockTokenAuthenticator creates a new mock instance.
func NewMockTokenAuthenticator(ctrl *gomock.Controller) *MockTokenAuthenticator {
	mock := &MockTokenAuthenticator{ctrl: ctrl}
	mock.recorder = &MockTokenAuthenticatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTokenAuthenticator) EXPECT() *MockTokenAuthenticatorMockRecorder {
	return m.recorder
}

// Authenticate mocks base method.
func (m *MockTokenAuthenticator) Authenticate(ctx context.Context, token string) (*TokenData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authenticate", ctx, token)
	ret0, _ := ret[0].(*TokenData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Authenticate indicates an expected call of Authenticate.
func (mr *MockTokenAuthenticatorMockRecorder) Authenticate(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authenticate", reflect.TypeOf((*MockTokenAuthenticator)(nil).Authenticate), ctx, token)
}

// AuthenticateKeycloakToken mocks base method.
func (m *MockTokenAuthenticator) AuthenticateKeycloakToken(ctx context.Context, token string) (*TokenData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateKeycloakToken", ctx, token)
	ret0, _ := ret[0].(*TokenData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateKeycloakToken indicates an expected call of AuthenticateKeycloakToken.
func (mr *MockTokenAuthenticatorMockRecorder) AuthenticateKeycloakToken(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateKeycloakToken", reflect.TypeOf((*MockTokenAuthenticator)(nil).AuthenticateKeycloakToken), ctx, token)
}
