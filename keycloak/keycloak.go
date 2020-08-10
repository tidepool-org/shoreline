package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	tokenPrefix         = "kc"
	tokenPartsSeparator = ":"
)

type User struct {
	ID            string         `json:"id"`
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
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RealmUrl     string `json:"realmUrl"`
}

type Client interface {
	Login(ctx context.Context, username, password string) (*oauth2.Token, error)
	IntrospectToken(ctx context.Context, token *oauth2.Token) (*TokenIntrospectionResult, error)
	RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
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
	return &client{
		keycloakConfig: config,
		oauth2Config:   cfg,
	}
}

func (c *client) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	log.Println(c.oauth2Config.Endpoint.AuthURL)
	return c.oauth2Config.PasswordCredentialsToken(ctx, username, password)
}

func (c *client) RevokeToken(ctx context.Context, token *oauth2.Token) error {
	endpoint := fmt.Sprintf("%v/protocol/openid-connect/revoke", c.keycloakConfig.RealmUrl)
	data := url.Values{
		"token":           []string{token.RefreshToken},
		"token_type_hint": []string{"refresh_token"},
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.oauth2Config.ClientID, c.oauth2Config.ClientSecret)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("received unexpected status %v from token revocation endpoint", resp.Status))
	}
	return nil
}

func (c *client) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	return c.oauth2Config.TokenSource(ctx, token).Token()
}

type TokenIntrospectionResult struct {
	Active        bool   `json:"active"`
	Subject       string `json:"sub"`
	EmailVerified bool   `json:"emailVerified"`
	ExpiresAt     int64  `json:"eat"`
}

func (c *client) IntrospectToken(ctx context.Context, token *oauth2.Token) (*TokenIntrospectionResult, error) {
	endpoint := fmt.Sprintf("%v/protocol/openid-connect/token/introspect", c.keycloakConfig.RealmUrl)
	data := url.Values{
		"token": []string{token.AccessToken},
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.oauth2Config.ClientID, c.oauth2Config.ClientSecret)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("received unexpected status %v from token introspection endpoint", resp.Status))
	}

	result := &TokenIntrospectionResult{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func IsKeycloakBackwardCompatibleToken(token string) bool {
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

func IsServiceToken(token *oauth2.Token) bool {
	// For the time being we're not using keycloak for service-to-service authentication
	return false
}