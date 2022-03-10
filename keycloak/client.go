package keycloak

import (
	"context"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v7"
	"github.com/Nerzal/gocloak/v7/pkg/jwx"
	"github.com/pkg/errors"
)

const (
	tokenPrefix         = "kc"
	tokenPartsSeparator = ":"
	masterRealm         = "master"
	serverRole          = "backend_service"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUserConflict = errors.New("user already exists")

//go:generate mockgen -source=./client.go -destination=./client_mock.go -package keycloak Client
type Client interface {
	Login(ctx context.Context, username, password string) (*oauth2.Token, error)
	GetBackendServiceToken(ctx context.Context) (*oauth2.Token, error)
	IntrospectToken(ctx context.Context, token oauth2.Token) (*TokenIntrospectionResult, error)
	RefreshToken(ctx context.Context, token oauth2.Token) (*oauth2.Token, error)
	RevokeToken(ctx context.Context, token oauth2.Token) error
	GetUserById(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	UpdateUserPassword(ctx context.Context, id, password string) error
	CreateUser(ctx context.Context, user *User) (*User, error)
	FindUsersWithIds(ctx context.Context, ids []string) ([]*User, error)
	DeleteUser(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, id string) error
}

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
	IsCustodial   *bool          `json:"-"`
}

type UserAttributes struct {
	TermsAcceptedDate []string `json:"terms_and_conditions,omitempty"`
}

func NewKeycloakUser(gocloakUser *gocloak.User) *User {
	if gocloakUser == nil {
		return nil
	}
	user := &User{
		ID:            safePStr(gocloakUser.ID),
		Username:      safePStr(gocloakUser.Username),
		FirstName:     safePStr(gocloakUser.FirstName),
		LastName:      safePStr(gocloakUser.LastName),
		Email:         safePStr(gocloakUser.Email),
		EmailVerified: safePBool(gocloakUser.EmailVerified),
		Enabled:       safePBool(gocloakUser.Enabled),
		IsCustodial:   gocloak.BoolP(true),
	}
	if gocloakUser.Attributes != nil {
		if ts, ok := (*gocloakUser.Attributes)["terms_and_conditions"]; ok {
			user.Attributes.TermsAcceptedDate = ts
		}
	}

	if gocloakUser.Credentials != nil {
		for _, c := range *gocloakUser.Credentials {
			if c.Type != nil && *c.Type == "password" {
				user.IsCustodial = gocloak.BoolP(false)
				break
			}
		}
	}

	if gocloakUser.RealmRoles != nil {
		user.Roles = *gocloakUser.RealmRoles
	}

	return user
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

func (t *TokenIntrospectionResult) IsServerToken() bool {
	if len(t.RealmAccess.Roles) > 0 {
		for _, role := range t.RealmAccess.Roles {
			if role == serverRole {
				return true
			}
		}
	}

	return false
}

type Config struct {
	ClientID            string `json:"clientId"`
	ClientSecret        string `json:"clientSecret"`
	BackendClientID     string `json:"backendClientId"`
	BackendClientSecret string `json:"backendClientSecret"`
	BaseUrl             string `json:"baseUrl"`
	Realm               string `json:"realm"`
	AdminUsername       string `json:"adminUsername"`
	AdminPassword       string `json:"adminPassword"`
}

func (c *Config) FromEnv() {
	if clientId, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_CLIENT_ID"); ok {
		c.ClientID = clientId
	}
	if clientSecret, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_CLIENT_SECRET"); ok {
		c.ClientSecret = clientSecret
	}
	if backendClientId, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_BACKEND_CLIENT_ID"); ok {
		c.BackendClientID = backendClientId
	}
	if backendClientSecret, ok := os.LookupEnv("TIDEPOOL_KEYCLOAK_BACKEND_CLIENT_SECRET"); ok {
		c.BackendClientSecret = backendClientSecret
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

type client struct {
	cfg                      *Config
	adminToken               *oauth2.Token
	adminTokenRefreshExpires time.Time
	keycloak                 gocloak.GoCloak
}

func NewClient(config *Config) Client {
	return &client{
		cfg:      config,
		keycloak: gocloak.NewClient(config.BaseUrl),
	}
}

func (c *client) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	jwt, err := c.keycloak.Login(
		ctx,
		c.cfg.ClientID,
		c.cfg.ClientSecret,
		c.cfg.Realm,
		username,
		password,
	)
	if err != nil {
		return nil, err
	}
	return c.jwtToAccessToken(jwt), nil
}

func (c *client) GetBackendServiceToken(ctx context.Context) (*oauth2.Token, error) {
	jwt, err := c.keycloak.LoginClient(ctx, c.cfg.BackendClientID, c.cfg.BackendClientSecret, c.cfg.Realm)
	if err != nil {
		return nil, err
	}
	return c.jwtToAccessToken(jwt), nil
}

func (c *client) jwtToAccessToken(jwt *gocloak.JWT) *oauth2.Token {
	if jwt == nil {
		return nil
	}
	return (&oauth2.Token{
		AccessToken:  jwt.AccessToken,
		TokenType:    jwt.TokenType,
		RefreshToken: jwt.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second),
	}).WithExtra(map[string]interface{}{
		"refresh_expires_in": jwt.RefreshExpiresIn,
	})
}

func (c *client) RevokeToken(ctx context.Context, token oauth2.Token) error {
	return c.keycloak.Logout(
		ctx,
		c.cfg.ClientID,
		c.cfg.ClientSecret,
		c.cfg.Realm,
		token.RefreshToken,
	)
}

func (c *client) RefreshToken(ctx context.Context, token oauth2.Token) (*oauth2.Token, error) {
	jwt, err := c.keycloak.RefreshToken(
		ctx,
		token.RefreshToken,
		c.cfg.ClientID,
		c.cfg.ClientSecret,
		c.cfg.Realm,
	)
	if err != nil {
		return nil, err
	}
	return c.jwtToAccessToken(jwt), nil
}

func (c *client) GetUserById(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, nil
	}

	users, err := c.FindUsersWithIds(ctx, []string{id})
	if err != nil || len(users) == 0 {
		return nil, err
	}

	return users[0], nil
}

func (c *client) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, nil
	}
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	users, err := c.keycloak.GetUsers(ctx, token.AccessToken, c.cfg.Realm, gocloak.GetUsersParams{
		Email: &email,
		Exact: gocloak.BoolP(true),
	})
	if err != nil || len(users) == 0 {
		return nil, err
	}

	return c.GetUserById(ctx, *users[0].ID)
}

func (c *client) UpdateUser(ctx context.Context, user *User) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	gocloakUser := gocloak.User{
		ID:            &user.ID,
		Username:      &user.Username,
		Enabled:       &user.Enabled,
		EmailVerified: &user.EmailVerified,
		FirstName:     &user.FirstName,
		LastName:      &user.LastName,
		Email:         &user.Email,
	}

	gocloakUser.Attributes = &map[string][]string{
		"terms_and_conditions": user.Attributes.TermsAcceptedDate,
	}

	if err := c.keycloak.UpdateUser(ctx, token.AccessToken, c.cfg.Realm, gocloakUser); err != nil {
		return err
	}
	if err := c.updateRolesForUser(ctx, user); err != nil {
		return err
	}
	return nil
}

func (c *client) UpdateUserPassword(ctx context.Context, id, password string) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	return c.keycloak.SetPassword(
		ctx,
		token.AccessToken,
		id,
		c.cfg.Realm,
		password,
		false,
	)
}

func (c *client) CreateUser(ctx context.Context, user *User) (*User, error) {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	user.ID, err = c.keycloak.CreateUser(ctx, token.AccessToken, c.cfg.Realm, gocloak.User{
		Username:   &user.Username,
		Email:      &user.Email,
		Enabled:    &user.Enabled,
		RealmRoles: &user.Roles,
	})
	if err != nil {
		if e, ok := err.(*gocloak.APIError); ok && e.Code == http.StatusConflict {
			err = ErrUserConflict
		}
		return nil, err
	}

	if err := c.updateRolesForUser(ctx, user); err != nil {
		return nil, err
	}

	return c.GetUserById(ctx, user.ID)
}

func (c *client) FindUsersWithIds(ctx context.Context, ids []string) (users []*User, err error) {
	const errMessage = "could not retrieve users by ids"

	token, err := c.getAdminToken(ctx)
	if err != nil {
		return
	}

	var res []*gocloak.User
	var errorResponse gocloak.HTTPErrorResponse
	response, err := c.keycloak.RestyClient().R().
		SetContext(ctx).
		SetError(&errorResponse).
		SetAuthToken(token.AccessToken).
		SetResult(&res).
		SetQueryParam("ids", strings.Join(ids, ",")).
		Get(c.getRealmURL(c.cfg.Realm, "tidepool-admin", "users"))

	err = checkForError(response, err, errMessage)
	if err != nil {
		return
	}

	users = make([]*User, len(res))
	for i, u := range res {
		users[i] = NewKeycloakUser(u)
	}

	return
}

func (c *client) IntrospectToken(ctx context.Context, token oauth2.Token) (*TokenIntrospectionResult, error) {
	rtr, err := c.keycloak.RetrospectToken(
		ctx,
		token.AccessToken,
		c.cfg.ClientID,
		c.cfg.ClientSecret,
		c.cfg.Realm,
	)
	if err != nil {
		return nil, err
	}

	result := &TokenIntrospectionResult{
		Active: safePBool(rtr.Active),
	}
	if result.Active {
		customClaims := &jwx.Claims{}
		_, err := c.keycloak.DecodeAccessTokenCustomClaims(
			ctx,
			token.AccessToken,
			c.cfg.Realm,
			"",
			customClaims,
		)
		if err != nil {
			return nil, err
		}
		result.Subject = customClaims.Subject
		result.EmailVerified = customClaims.EmailVerified
		result.ExpiresAt = customClaims.ExpiresAt.Unix()
		result.RealmAccess = RealmAccess{
			Roles: customClaims.RealmAccess.Roles,
		}
	}

	return result, nil
}

func (c *client) DeleteUser(ctx context.Context, id string) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	if err := c.keycloak.DeleteUser(ctx, token.AccessToken, c.cfg.Realm, id); err != nil {
		if aErr, ok := err.(*gocloak.APIError); ok && aErr.Code == http.StatusNotFound {
			return nil
		}
	}
	return err
}

func (c *client) DeleteUserSessions(ctx context.Context, id string) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	if err := c.keycloak.LogoutAllSessions(ctx, token.AccessToken, c.cfg.Realm, id); err != nil {
		if aErr, ok := err.(*gocloak.APIError); ok && aErr.Code == http.StatusNotFound {
			return nil
		}
	}

	return err
}

func (c *client) getRealmURL(realm string, path ...string) string {
	path = append([]string{c.cfg.BaseUrl, "auth", "realms", realm}, path...)
	return strings.Join(path, "/")
}

func (c *client) getAdminToken(ctx context.Context) (*oauth2.Token, error) {
	var err error
	if c.adminTokenIsExpired() {
		err = c.loginAsAdmin(ctx)
	}

	return c.adminToken, err
}

func (c *client) loginAsAdmin(ctx context.Context) error {
	jwt, err := c.keycloak.LoginAdmin(
		ctx,
		c.cfg.AdminUsername,
		c.cfg.AdminPassword,
		masterRealm,
	)
	if err != nil {
		return err
	}

	c.adminToken = c.jwtToAccessToken(jwt)
	c.adminTokenRefreshExpires = time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second)
	return nil
}

func (c *client) adminTokenIsExpired() bool {
	return c.adminToken == nil || time.Now().After(c.adminTokenRefreshExpires)
}

func (c *client) updateRolesForUser(ctx context.Context, user *User) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	realmRoles, err := c.keycloak.GetRealmRoles(ctx, token.AccessToken, c.cfg.Realm)
	if err != nil {
		return err
	}
	currentUserRoles, err := c.keycloak.GetRealmRolesByUserID(ctx, token.AccessToken, c.cfg.Realm, user.ID)
	if err != nil {
		return err
	}

	var rolesToAdd []gocloak.Role
	var rolesToDelete []gocloak.Role

	targetRoles := make(map[string]struct{})
	if len(user.Roles) > 0 {
		for _, targetRoleName := range user.Roles {
			targetRoles[targetRoleName] = struct{}{}
		}
	}

	for targetRoleName, _ := range targetRoles {
		realmRole := getRealmRoleByName(realmRoles, targetRoleName)
		if realmRole != nil {
			rolesToAdd = append(rolesToAdd, *realmRole)
		}
	}

	if len(currentUserRoles) > 0 {
		for _, currentRole := range currentUserRoles {
			if currentRole == nil || currentRole.Name == nil || *currentRole.Name == "" {
				continue
			}

			if _, ok := targetRoles[*currentRole.Name]; !ok {
					rolesToDelete = append(rolesToDelete, *currentRole)
			}
		}
	}

	if len(rolesToAdd) > 0 {
		if err = c.keycloak.AddRealmRoleToUser(ctx, token.AccessToken, c.cfg.Realm, user.ID, rolesToAdd); err != nil {
			return err
		}
	}
	if len(rolesToDelete) > 0 {
		if err = c.keycloak.DeleteRealmRoleFromUser(ctx, token.AccessToken, c.cfg.Realm, user.ID, rolesToAdd); err != nil {
			return err
		}
	}

	return nil
}

func getRealmRoleByName(realmRoles []*gocloak.Role, name string) *gocloak.Role {
	for _, realmRole := range realmRoles {
		if realmRole.Name != nil && *realmRole.Name == name {
			return realmRole
		}
	}

	return nil
}
