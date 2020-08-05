package keycloak

import (
	"context"
	"golang.org/x/oauth2"
)

type MockClient struct {
}

func (m *MockClient) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  "YYYYYY",
		RefreshToken: "XXXXXX",
	}, nil
}

func (m *MockClient) RevokeToken(ctx context.Context, token *oauth2.Token) error {
	return nil
}
