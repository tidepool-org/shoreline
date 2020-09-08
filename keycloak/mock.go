package keycloak

import (
	"context"
	"errors"
	"golang.org/x/oauth2"
	"time"
)

type MockClient struct {
}

var _ Client = &MockClient{}

func (m *MockClient) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  "YYYYYY",
		RefreshToken: "XXXXXX",
	}, nil
}

func (m *MockClient) RevokeToken(ctx context.Context, token *oauth2.Token) error {
	return nil
}

func (m *MockClient) IntrospectToken(ctx context.Context, token *oauth2.Token) (*TokenIntrospectionResult, error) {
	return &TokenIntrospectionResult{
		Active:        true,
		Subject:       "70dd70dd70",
		EmailVerified: true,
		ExpiresAt:     time.Now().Unix() + 600,
	}, nil
}

func (m *MockClient) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	return token, nil
}

func (m *MockClient) GetUserById(ctx context.Context, id string) (*User, error) {
	return nil, ErrUserNotFound
}

func (m *MockClient) GetUserByEmail(ctx context.Context, username string) (*User, error) {
	return nil, ErrUserNotFound
}

func (m *MockClient) UpdateUser(ctx context.Context, user *User) error {
	return nil
}

func (m *MockClient) UpdateUserPassword(ctx context.Context, id, password string) error {
	return nil
}

func (m *MockClient) CreateUser(ctx context.Context, user *User) (*User, error) {
	return nil, errors.New("not implemented")
}

func (m *MockClient) FindUsersWithIds(ctx context.Context, ids []string) ([]*User, error) {
	return nil, errors.New("not implemented")
}
