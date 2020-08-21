package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	tokenPrefix            = "kc"
	tokenPartsSeparator    = ":"
	masterRealm            = "master"
	authzEndpointPath      = "/protocol/openid-connect/auth"
	tokenEndpointPath      = "/protocol/openid-connect/token"
	introspectEndpointPath = "/protocol/openid-connect/token/introspect"
	revocationEndpointPath = "/protocol/openid-connect/revoke"
)

var ErrUserNotFound = errors.New("user not found")

type User struct {
	ID            string         `json:"id"`
	Username      string         `json:"username,omitempty"`
	Email         string         `json:"email,omitempty"`
	FirstName     string         `json:"firstName,omitempty"`
	LastName      string         `json:"lastName,omitempty"`
	Enabled       bool           `json:"enabled,omitempty"`
	EmailVerified bool           `json:"emailVerified,omitempty"`
	Roles         []string       `json:"roles,omitempty"`
	Attributes    UserAttributes `json:"attributes"`
}

type UserAttributes struct {
	TermsAccepted     []string `json:"termsAccepted"`
	TermsAcceptedDate []string `json:"termsAcceptedDate,omitempty"`
}

type CheckPasswordRequest struct {
	Password string `json:"password"`
}

type Config struct {
	ClientID      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret"`
	BaseUrl       string `json:"baseUrl"`
	Realm         string `json:"realm"`
	AdminClientId string `json:"admin-cli"`
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
			AuthURL:  c.AuthorizationEndpoint(realm),
			TokenURL: c.TokenEndpoint(realm),
		},
	}
}

func (c *Config) AdminOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID: "admin-cli",
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.AuthorizationEndpoint(masterRealm),
			TokenURL: c.TokenEndpoint(masterRealm),
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
	r := strings.Join([]string{c.BaseUrl, "auth", "realms", realm}, "/")
	if endpoint == "" {
		return r
	}
	return strings.Join([]string{r, endpoint}, "")
}

type Client interface {
	Login(ctx context.Context, username, password string) (*oauth2.Token, error)
	IntrospectToken(ctx context.Context, token *oauth2.Token) (*TokenIntrospectionResult, error)
	RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
	RevokeToken(ctx context.Context, token *oauth2.Token) error
	GetUserById(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	UpdateUserPassword(ctx context.Context, id, password string) error
}

type client struct {
	keycloakConfig           *Config
	userOauth                *oauth2.Config
	adminOauth               *oauth2.Config
	adminToken               *oauth2.Token
	adminTokenRefreshExpires time.Time
}

func NewClient(config *Config) Client {
	return &client{
		keycloakConfig: config,
		userOauth:      config.OAuth2Config(config.Realm),
		adminOauth:     config.AdminOauthConfig(),
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
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}
	client := c.adminOauth.Client(ctx, token)
	endpoint := strings.Join([]string{c.keycloakConfig.BaseUrl, "auth", "admin", "realms", c.keycloakConfig.Realm, "users", id}, "/")
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
	} else if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("unexpected status code %v when retrieveing user", resp.StatusCode))
	}

	user := &User{}
	if err := json.NewDecoder(resp.Body).Decode(user); err != nil {
		return nil, err
	}

	roles, err := c.getRolesForUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Roles = roles

	return user, nil
}

func (c *client) GetUserByEmail(ctx context.Context, username string) (*User, error) {
	if username == "" {
		return nil, nil
	}
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}
	client := c.adminOauth.Client(ctx, token)
	endpoint := strings.Join([]string{c.keycloakConfig.BaseUrl, "auth", "admin", "realms", c.keycloakConfig.Realm, "users"}, "/")
	query := fmt.Sprintf("username=%s&exact=true", url.QueryEscape(username))
	requestUrl := fmt.Sprintf("%s?%s", endpoint, query)
	req, err := http.NewRequest(http.MethodGet, requestUrl, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("unexpected status code %v when retrieveing users", resp.StatusCode))
	}

	var users []User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	if len(users) != 1 {
		return nil, ErrUserNotFound
	}

	user := users[0]
	roles, err := c.getRolesForUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	user.Roles = roles

	return &user, nil
}

func (c *client) UpdateUser(ctx context.Context, user *User) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}
	client := c.adminOauth.Client(ctx, token)
	endpoint := strings.Join([]string{c.keycloakConfig.BaseUrl, "auth", "admin", "realms", c.keycloakConfig.Realm, "users", user.ID}, "/")


	body, err := json.Marshal(user)
	if err != nil {
		return err
	}
	fmt.Printf(string(body))
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Add("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		return errors.New(fmt.Sprintf("unexpected status code %v when updating user", resp.StatusCode))
	}

	return nil
}

type resetPasswordBody struct {
	Typ string `json:"type"`
	Temporary bool `json:"temporary"`
	Value string `json:"value"`
}

func (c *client) UpdateUserPassword(ctx context.Context, id, password string) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}
	client := c.adminOauth.Client(ctx, token)
	endpoint := strings.Join([]string{c.keycloakConfig.BaseUrl, "auth", "admin", "realms", c.keycloakConfig.Realm, "users", id, "reset-password"}, "/")


	body, err := json.Marshal(resetPasswordBody{
		Typ:       "password",
		Temporary: false,
		Value:     password,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Add("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		return errors.New(fmt.Sprintf("unexpected status code %v when updating user password", resp.StatusCode))
	}

	return nil
}

func (c *client) getAdminToken(ctx context.Context) (*oauth2.Token, error) {
	if c.canRefreshAdminToken() {
		if err := c.refreshAdminToken(ctx); err != nil {
			return nil, err
		}
	} else {
		c.adminToken = nil
	}

	if c.adminToken == nil {
		var err error
		if c.adminToken, err = c.adminOauth.PasswordCredentialsToken(ctx, c.keycloakConfig.AdminUsername, c.keycloakConfig.AdminPassword); err != nil {
			return nil, err
		}
	}

	return c.adminToken, nil
}

func (c *client) refreshAdminToken(ctx context.Context) error {
	tokenSource := c.adminOauth.TokenSource(ctx, c.adminToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return err
	}
	if c.adminToken == nil || newToken.AccessToken != c.adminToken.AccessToken {
		c.adminToken = newToken
		expires := newToken.Extra("refresh_expires_in")
		if expires != nil {
			if val, ok := expires.(int); ok {
				c.adminTokenRefreshExpires = time.Now().Add(time.Duration(int64(val) * int64(time.Second)))
			}
		}
	}
	return nil
}

func (c *client) canRefreshAdminToken() bool {
	return c.adminToken != nil && c.adminTokenRefreshExpires.After(time.Now())
}

type role struct {
	Name string
}

func (c *client) getRolesForUser(ctx context.Context, id string) ([]string, error) {
	client := c.adminOauth.Client(ctx, c.adminToken)
	endpoint := strings.Join([]string{
		c.keycloakConfig.BaseUrl,
		"auth", "admin", "realms",
		c.keycloakConfig.Realm,
		"users", id,
		"role-mappings", "realm"},
		"/")
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("unexpected status code %v when retrieveing user roles", resp.StatusCode))
	}

	var roles []role
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, err
	}

	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}

	return roleNames, nil
}

type TokenIntrospectionResult struct {
	Active        bool        `json:"active"`
	Subject       string      `json:"sub"`
	EmailVerified bool        `json:"email_verified"`
	ExpiresAt     int64       `json:"eat"`
	RealmAccess   RealmAccess `json:"realm_access"`
}

type RealmAccess struct {
	Roles []string `json:"roles"`
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
