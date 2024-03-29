package keycloak

import (
	"context"
	"github.com/Nerzal/gocloak/v12"
	"github.com/Nerzal/gocloak/v12/pkg/jwx"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	tokenPrefix         = "kc"
	tokenPartsSeparator = ":"
	masterRealm         = "master"
	serverRole          = "backend_service"
)

var shorelineManagedRoles = map[string]struct{}{"patient": {}, "clinic": {}, "clinician": {}, "custodial_account": {}}

var ErrUserNotFound = errors.New("user not found")
var ErrUserConflict = errors.New("user already exists")

//go:generate mockgen -source=./client.go -destination=./client_mock.go -package keycloak Client
type Client interface {
	Login(ctx context.Context, username, password string) (*oauth2.Token, error)
	LoginLongLived(ctx context.Context, username, password string) (*oauth2.Token, error)
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
	}
	if gocloakUser.Attributes != nil {
		if ts, ok := (*gocloakUser.Attributes)["terms_and_conditions"]; ok {
			user.Attributes.TermsAcceptedDate = ts
		}
	}

	if gocloakUser.RealmRoles != nil {
		user.Roles = *gocloakUser.RealmRoles
	}

	return user
}

type TokenIntrospectionResult struct {
	Active           bool        `json:"active"`
	Subject          string      `json:"sub"`
	EmailVerified    bool        `json:"email_verified"`
	ExpiresAt        int64       `json:"eat"`
	RealmAccess      RealmAccess `json:"realm_access"`
	IdentityProvider string      `json:"identityProvider"`
}

type AccessTokenCustomClaims struct {
	jwx.Claims
	IdentityProvider string `json:"identity_provider,omitempty"`
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
	ClientID              string `envconfig:"TIDEPOOL_KEYCLOAK_CLIENT_ID" required:"true"`
	ClientSecret          string `envconfig:"TIDEPOOL_KEYCLOAK_CLIENT_SECRET" required:"true"`
	LongLivedClientID     string `envconfig:"TIDEPOOL_KEYCLOAK_LONG_LIVED_CLIENT_ID" required:"true"`
	LongLivedClientSecret string `envconfig:"TIDEPOOL_KEYCLOAK_LONG_LIVED_CLIENT_SECRET" required:"true"`
	BackendClientID       string `envconfig:"TIDEPOOL_KEYCLOAK_BACKEND_CLIENT_ID" required:"true"`
	BackendClientSecret   string `envconfig:"TIDEPOOL_KEYCLOAK_BACKEND_CLIENT_SECRET" required:"true"`
	BaseUrl               string `envconfig:"TIDEPOOL_KEYCLOAK_BASE_URL" required:"true"`
	Realm                 string `envconfig:"TIDEPOOL_KEYCLOAK_REALM" required:"true"`
	AdminUsername         string `envconfig:"TIDEPOOL_KEYCLOAK_ADMIN_USERNAME" required:"true"`
	AdminPassword         string `envconfig:"TIDEPOOL_KEYCLOAK_ADMIN_PASSWORD" required:"true"`
}

func (c *Config) FromEnv() error {
	return envconfig.Process("", c)
}

type client struct {
	cfg                      *Config
	adminToken               *oauth2.Token
	adminTokenRefreshExpires time.Time
	keycloak                 *gocloak.GoCloak
}

func NewClient(config *Config) Client {
	return &client{
		cfg:      config,
		keycloak: gocloak.NewClient(config.BaseUrl),
	}
}

func (c *client) Login(ctx context.Context, username, password string) (*oauth2.Token, error) {
	return c.doLogin(ctx, c.cfg.ClientID, c.cfg.ClientSecret, username, password)
}

func (c *client) LoginLongLived(ctx context.Context, username, password string) (*oauth2.Token, error) {
	return c.doLogin(ctx, c.cfg.LongLivedClientID, c.cfg.LongLivedClientSecret, username, password)
}

func (c *client) doLogin(ctx context.Context, clientId, clientSecret, username, password string) (*oauth2.Token, error) {
	jwt, err := c.keycloak.Login(
		ctx,
		clientId,
		clientSecret,
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
	clientId, clientSecret := c.getClientAndSecretFromToken(ctx, token)
	return c.keycloak.Logout(
		ctx,
		clientId,
		clientSecret,
		c.cfg.Realm,
		token.RefreshToken,
	)
}

func (c *client) RefreshToken(ctx context.Context, token oauth2.Token) (*oauth2.Token, error) {
	clientId, clientSecret := c.getClientAndSecretFromToken(ctx, token)

	jwt, err := c.keycloak.RefreshToken(
		ctx,
		token.RefreshToken,
		clientId,
		clientSecret,
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

	model := gocloak.User{
		Username:      &user.Username,
		Email:         &user.Email,
		EmailVerified: &user.EmailVerified,
		Enabled:       &user.Enabled,
		RealmRoles:    &user.Roles,
	}

	if len(user.Attributes.TermsAcceptedDate) > 0 {
		attrs := map[string][]string{
			"terms_and_conditions": user.Attributes.TermsAcceptedDate,
		}
		model.Attributes = &attrs
	}

	user.ID, err = c.keycloak.CreateUser(ctx, token.AccessToken, c.cfg.Realm, model)
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
	clientId, clientSecret := c.getClientAndSecretFromToken(ctx, token)

	rtr, err := c.keycloak.RetrospectToken(
		ctx,
		token.AccessToken,
		clientId,
		clientSecret,
		c.cfg.Realm,
	)
	if err != nil {
		return nil, err
	}

	result := &TokenIntrospectionResult{
		Active: safePBool(rtr.Active),
	}
	if result.Active {
		customClaims := &AccessTokenCustomClaims{}
		_, err := c.keycloak.DecodeAccessTokenCustomClaims(
			ctx,
			token.AccessToken,
			c.cfg.Realm,
			customClaims,
		)
		if err != nil {
			return nil, err
		}
		result.Subject = customClaims.Subject
		result.EmailVerified = customClaims.EmailVerified
		result.ExpiresAt = customClaims.ExpiresAt
		result.RealmAccess = RealmAccess{
			Roles: customClaims.RealmAccess.Roles,
		}
		result.IdentityProvider = customClaims.IdentityProvider
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
	path = append([]string{c.cfg.BaseUrl, "realms", realm}, path...)
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

	realmRoles, err := c.keycloak.GetRealmRoles(ctx, token.AccessToken, c.cfg.Realm, gocloak.GetRoleParams{
		Max: gocloak.IntP(1000),
	})
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
				// Only remove roles managed by shoreline
				if _, ok := shorelineManagedRoles[*currentRole.Name]; ok {
					rolesToDelete = append(rolesToDelete, *currentRole)
				}
			}
		}
	}

	if len(rolesToAdd) > 0 {
		if err = c.keycloak.AddRealmRoleToUser(ctx, token.AccessToken, c.cfg.Realm, user.ID, rolesToAdd); err != nil {
			return err
		}
	}
	if len(rolesToDelete) > 0 {
		if err = c.keycloak.DeleteRealmRoleFromUser(ctx, token.AccessToken, c.cfg.Realm, user.ID, rolesToDelete); err != nil {
			return err
		}
	}

	return nil
}

func (c *client) getClientAndSecretFromToken(ctx context.Context, token oauth2.Token) (string, string) {
	clientId := c.cfg.ClientID
	clientSecret := c.cfg.ClientSecret

	customClaims := &jwx.Claims{}
	_, err := c.keycloak.DecodeAccessTokenCustomClaims(
		ctx,
		token.AccessToken,
		c.cfg.Realm,
		customClaims,
	)

	if err == nil && customClaims.Azp == c.cfg.LongLivedClientID {
		clientId = c.cfg.LongLivedClientID
		clientSecret = c.cfg.LongLivedClientSecret
	}

	return clientId, clientSecret
}

func getRealmRoleByName(realmRoles []*gocloak.Role, name string) *gocloak.Role {
	for _, realmRole := range realmRoles {
		if realmRole.Name != nil && *realmRole.Name == name {
			return realmRole
		}
	}

	return nil
}
