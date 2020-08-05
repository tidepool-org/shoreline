package keycloak

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
)

const (
	tokenPrefix         = "kc"
	tokenPartsSeparator = ":"
)

type User struct {
	Username      string         `json:"username"`
	Email         string         `json:"email"`
	FirstName     string         `json:"firstName"`
	LastName      string         `json:"lastName"`
	Enabled       bool           `json:"enabled"`
	EmailVerified bool           `json:"emailVerified"`
	Roles         []string       `json:"roles"`
	Attributes    UserAttributes `json:"attributes"`
}

type UserAttributes struct {
	TermsAccepted []string `json:"termsAccepted"`
}

type CheckPasswordRequest struct {
	Password string `json:"password"`
}

type Config struct {
	ClientID     string
	ClientSecret string
	RealmUrl     string
}

type Client interface {
	Login(ctx context.Context, username, password string) (*oauth2.Token, error)
	RevokeToken(ctx context.Context, token *oauth2.Token) error
}

type client struct {
	keycloakConfig *Config
	oauth2Config   oauth2.Config
}

func NewClient(config *Config) Client {
	cfg := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%v/protocol/openid-connect/auth", config.RealmUrl),
			TokenURL: fmt.Sprintf("%v/protocol/openid-connect/token", config.RealmUrl),
		},
	}
	return &client{oauth2Config: cfg}
}

func (c *client) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	return c.oauth2Config.PasswordCredentialsToken(ctx, username, password)
}

func (c *client) RevokeToken(ctx context.Context, token *oauth2.Token) error {
	client := http.Client{}
	endpoint := fmt.Sprintf("%v/protocol/openid-connect/revoke", c.keycloakConfig.RealmUrl)
	data := url.Values{
		"token":           []string{token.RefreshToken},
		"token_type_hint": []string{"refresh"},
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.oauth2Config.ClientID, c.oauth2Config.ClientSecret)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("received unexpected status %v from token revocation endpoint", resp.Status))
	}
	return nil
}

func IsKeycloakToken(token string) bool {
	_, err := UnpackBackwardCompatibleToken(token)
	return err == nil
}

func CreateBackwardCompatibleToken(token *oauth2.Token) (backwardCompatibleToken string, err error) {
	if token.AccessToken == "" {
		err = errors.New("access token can't be empty")
		return
	}
	if token.RefreshToken == "" {
		err = errors.New("refresh token can't be empty")
		return
	}

	// Legacy tokens were used for refreshing session, thus we also need to encode the oauth2 refresh token
	// for providing a backward-compatible refresh token endpoint.
	backwardCompatibleToken = strings.Join(
		[]string{tokenPrefix, token.AccessToken, token.RefreshToken},
		tokenPartsSeparator,
	)
	return
}

func UnpackBackwardCompatibleToken(token string) (*oauth2.Token, error) {
	parts := strings.Split(token, tokenPartsSeparator)
	if len(parts) != 3 || parts[0] != tokenPrefix || parts[1] == "" || parts[2] == "" {
		return nil, errors.New("invalid keycloak token")
	}
	t := &oauth2.Token{
		AccessToken:  parts[1],
		RefreshToken: parts[2],
	}
	return t, nil
}
