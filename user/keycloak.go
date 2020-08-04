package user

import "context"

type KeycloakUser struct {
	Username      string                 `json:"username"`
	Email         string                 `json:"email"`
	FirstName     string                 `json:"firstName"`
	LastName      string                 `json:"lastName"`
	Enabled       bool                   `json:"enabled"`
	EmailVerified bool                   `json:"emailVerified"`
	Roles         []string               `json:"roles"`
	Attributes    KeycloakUserAttributes `json:"attributes"`
}

type KeycloakUserAttributes struct {
	TermsAccepted []string `json:"termsAccepted"`
}

type CheckPasswordRequest struct {
	Password string `json:"password"`
}

type KeycloakClient struct {
	clientId     string
	clientSecret string
}

func (*KeycloakClient) Login(ctx context.Context, username, password string) (string, error) {
	return "", nil
}

func (*KeycloakClient) Logout(ctx context.Context, token string) error {
	return nil
}

func (*KeycloakClient) IsKeycloakToken(token string) bool {
	return false
}
