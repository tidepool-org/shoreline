package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	tokenPrefix            = "kc"
	tokenPartsSeparator    = ":"
	masterRealm            = "master"
	authzEndpointPath      = "/protocol/openid-connect/auth"
	tokenEndpointPath      = "/protocol/openid-connect/token"
	introspectEndpointPath = "/protocol/openid-connect/token/introspect"
	revocationEndpointPath = "/protocol/openid-connect/token/revoke"
)

var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID            string         `json:"id"`
	Username      string         `json:"username"`
	Email         string         `json:"email"`
	FirstName     string         `json:"firstName"`
	LastName      string         `json:"lastName"`
	Enabled       bool           `json:"enabled"`
	EmailVerified bool           `json:"emailVerified"`
	Roles         []string       `json:"roles"`
	RealmRoles    []string       `json:"realmRoles,omitempty"`
	Attributes    UserAttributes `json:"attributes"`
}

type UserAttributes struct {
	TermsAccepted     []string `json:"termsAccepted"`
	TermsAcceptedDate []string `json:"termsAcceptedDate"`
}

type CheckPasswordRequest struct {
	Password string `json:"password"`
}

type Config struct {
	ClientID      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret"`
	BaseUrl       string `json:"baseUrl"`
	Realm         string `json:"realm"`
	AdminUsername string `json:"adminUsername"`
	AdminPassword string `json:"adminPassword"`
}

func (c *Config) FromEnv() {
	if clientId, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_CLIENT_ID"); ok {
		c.ClientID = clientId
	}
	if clientSecret, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_CLIENT_SECRET"); ok {
		c.ClientSecret = clientSecret
	}
	if baseUrl, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_BASE_URL"); ok {
		c.BaseUrl = baseUrl
	}
	if realm, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_REALM"); ok {
		c.Realm = realm
	}
	if username, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_ADMIN_USERNAME"); ok {
		c.AdminUsername = username
	}
	if password, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_ADMIN_PASSWORD"); ok {
		c.AdminPassword = password
	}
}

func (c *Config) OAuth2Config(realm string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.realmUrl(realm, c.AuthorizationEndpoint(realm)),
			TokenURL: c.realmUrl(realm, c.TokenEndpoint(realm)),
		},
	}
}

func (c *Config) AuthorizationEndpoint(realm string) string {
	return c.realmUrl(realm, authzEndpointPath)
}

func (c *Config) TokenEndpoint(realm string) string {
	return c.realmUrl(realm, tokenEndpointPath)
}

func (c *Config) TokenRevocationEndpoint(realm string) string {
	return c.realmUrl(realm, revocationEndpointPath)
}

func (c *Config) TokenIntrospectionEndpoint(realm string) string {
	return c.realmUrl(realm, introspectEndpointPath)
}

func (c *Config) realmUrl(realm, endpoint string) string {
	realmUrl := strings.Join([]string{c.BaseUrl, "auth", "realms", realm}, "/")
	if endpoint == "" {
		return realmUrl
	}
	return strings.Join([]string{realmUrl, endpoint}, "")
}

type Client interface {
	Login(ctx context.Context, username, password string) (*oauth2.Token, error)
	IntrospectToken(ctx context.Context, token *oauth2.Token) (*TokenIntrospectionResult, error)
	RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
	RevokeToken(ctx context.Context, token *oauth2.Token) error
	GetUserById(ctx context.Context, id string) (*User, error)
}

type client struct {
	keycloakConfig *Config
	userOauth      *oauth2.Config
	adminOauth     *oauth2.Config
	adminToken     *oauth2.Token
}

func NewClient(config *Config) Client {
	return &client{
		keycloakConfig: config,
		userOauth:      config.OAuth2Config(config.Realm),
		adminOauth:     config.OAuth2Config(masterRealm),
	}
}

func (c *client) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	return c.userOauth.PasswordCredentialsToken(ctx, username, password)
}

func (c *client) RevokeToken(ctx context.Context, token *oauth2.Token) error {
	endpoint := c.keycloakConfig.TokenRevocationEndpoint(c.keycloakConfig.Realm)
	data := url.Values{
		"token":           []string{token.RefreshToken},
		"token_type_hint": []string{"refresh_token"},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.userOauth.ClientID, c.userOauth.ClientSecret)

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
	return c.userOauth.TokenSource(ctx, token).Token()
}

func (c *client) GetUserById(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, nil
	}
	if c.adminToken == nil {
		token, err := c.adminOauth.PasswordCredentialsToken(ctx, c.keycloakConfig.AdminUsername, c.keycloakConfig.AdminPassword)
		if err != nil {
			return nil, err
		}
		c.adminToken = token
	}

	client := c.adminOauth.Client(ctx, c.adminToken)
	endpoint := strings.Join([]string{c.keycloakConfig.BaseUrl, "auth", c.keycloakConfig.Realm, "users", id}, "/")
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrUserNotFound
	}
	user := &User{}
	if err := json.NewDecoder(resp.Body).Decode(user); err != nil {
		return nil, err
	}
	user.Roles = user.RealmRoles
	user.RealmRoles = nil
	
	return user, nil
}

type TokenIntrospectionResult struct {
	Active        bool   `json:"active"`
	Subject       string `json:"sub"`
	EmailVerified bool   `json:"emailVerified"`
	ExpiresAt     int64  `json:"eat"`
}

func (t *TokenIntrospectionResult) HasServerScope() bool {
	return false
}

func (c *client) IntrospectToken(ctx context.Context, token *oauth2.Token) (*TokenIntrospectionResult, error) {
	endpoint := c.keycloakConfig.TokenIntrospectionEndpoint(c.keycloakConfig.Realm)
	data := url.Values{
		"token": []string{token.AccessToken},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.userOauth.ClientID, c.userOauth.ClientSecret)

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
