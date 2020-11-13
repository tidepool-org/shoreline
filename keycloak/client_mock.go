// Code generated by MockGen. DO NOT EDIT.
// Source: ./client.go

// Package keycloak is a generated GoMock package.
package keycloak

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	oauth2 "golang.org/x/oauth2"
	reflect "reflect"
)

// MockClient is a mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// Login mocks base method
func (m *MockClient) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Login", ctx, username, password)
	ret0, _ := ret[0].(*oauth2.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Login indicates an expected call of Login
func (mr *MockClientMockRecorder) Login(ctx, username, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Login", reflect.TypeOf((*MockClient)(nil).Login), ctx, username, password)
}

// GetServiceAccountToken mocks base method
func (m *MockClient) GetServiceAccountToken(ctx context.Context) (*oauth2.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServiceAccountToken", ctx)
	ret0, _ := ret[0].(*oauth2.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetServiceAccountToken indicates an expected call of GetServiceAccountToken
func (mr *MockClientMockRecorder) GetServiceAccountToken(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceAccountToken", reflect.TypeOf((*MockClient)(nil).GetServiceAccountToken), ctx)
}

// IntrospectToken mocks base method
func (m *MockClient) IntrospectToken(ctx context.Context, token oauth2.Token) (*TokenIntrospectionResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IntrospectToken", ctx, token)
	ret0, _ := ret[0].(*TokenIntrospectionResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IntrospectToken indicates an expected call of IntrospectToken
func (mr *MockClientMockRecorder) IntrospectToken(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IntrospectToken", reflect.TypeOf((*MockClient)(nil).IntrospectToken), ctx, token)
}

// RefreshToken mocks base method
func (m *MockClient) RefreshToken(ctx context.Context, token oauth2.Token) (*oauth2.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RefreshToken", ctx, token)
	ret0, _ := ret[0].(*oauth2.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RefreshToken indicates an expected call of RefreshToken
func (mr *MockClientMockRecorder) RefreshToken(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RefreshToken", reflect.TypeOf((*MockClient)(nil).RefreshToken), ctx, token)
}

// RevokeToken mocks base method
func (m *MockClient) RevokeToken(ctx context.Context, token oauth2.Token) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RevokeToken", ctx, token)
	ret0, _ := ret[0].(error)
	return ret0
}

// RevokeToken indicates an expected call of RevokeToken
func (mr *MockClientMockRecorder) RevokeToken(ctx, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RevokeToken", reflect.TypeOf((*MockClient)(nil).RevokeToken), ctx, token)
}

// GetUserById mocks base method
func (m *MockClient) GetUserById(ctx context.Context, id string) (*User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserById", ctx, id)
	ret0, _ := ret[0].(*User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserById indicates an expected call of GetUserById
func (mr *MockClientMockRecorder) GetUserById(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserById", reflect.TypeOf((*MockClient)(nil).GetUserById), ctx, id)
}

// GetUserByEmail mocks base method
func (m *MockClient) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByEmail", ctx, email)
	ret0, _ := ret[0].(*User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByEmail indicates an expected call of GetUserByEmail
func (mr *MockClientMockRecorder) GetUserByEmail(ctx, email interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByEmail", reflect.TypeOf((*MockClient)(nil).GetUserByEmail), ctx, email)
}

// UpdateUser mocks base method
func (m *MockClient) UpdateUser(ctx context.Context, user *User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", ctx, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUser indicates an expected call of UpdateUser
func (mr *MockClientMockRecorder) UpdateUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockClient)(nil).UpdateUser), ctx, user)
}

// UpdateUserPassword mocks base method
func (m *MockClient) UpdateUserPassword(ctx context.Context, id, password string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserPassword", ctx, id, password)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUserPassword indicates an expected call of UpdateUserPassword
func (mr *MockClientMockRecorder) UpdateUserPassword(ctx, id, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserPassword", reflect.TypeOf((*MockClient)(nil).UpdateUserPassword), ctx, id, password)
}

// CreateUser mocks base method
func (m *MockClient) CreateUser(ctx context.Context, user *User) (*User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", ctx, user)
	ret0, _ := ret[0].(*User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser
func (mr *MockClientMockRecorder) CreateUser(ctx, user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockClient)(nil).CreateUser), ctx, user)
}

// FindUsersWithIds mocks base method
func (m *MockClient) FindUsersWithIds(ctx context.Context, ids []string) ([]*User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindUsersWithIds", ctx, ids)
	ret0, _ := ret[0].([]*User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindUsersWithIds indicates an expected call of FindUsersWithIds
func (mr *MockClientMockRecorder) FindUsersWithIds(ctx, ids interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindUsersWithIds", reflect.TypeOf((*MockClient)(nil).FindUsersWithIds), ctx, ids)
}
