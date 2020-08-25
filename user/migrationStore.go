package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/tidepool-org/shoreline/keycloak"
)

var ErrUserConflict = errors.New("user already exists")

type MigrationStore struct {
	ctx            context.Context
	fallback       Storage
	keycloakClient keycloak.Client
}

func NewMigrationStore(fallback Storage, keycloakClient keycloak.Client) *MigrationStore {
	return &MigrationStore{
		fallback:       fallback,
		keycloakClient: keycloakClient,
	}
}

func (m *MigrationStore) Ping() error {
	return m.fallback.Ping()
}

func (m *MigrationStore) WithContext(ctx context.Context) Storage {
	if ctx == nil {
		panic("nil context")
	}

	return &MigrationStore{
		ctx:            ctx,
		fallback:       m.fallback.WithContext(ctx),
		keycloakClient: m.keycloakClient,
	}
}

func (m *MigrationStore) EnsureIndexes() error {
	return m.fallback.EnsureIndexes()
}

func (m *MigrationStore) CreateUser(details *NewUserDetails) (*User, error) {
	user := &keycloak.User{
		Email:         *details.Username,
		Enabled:       true,
		EmailVerified: false,
		Roles:         TidepoolRolesToKeycloakRoles(details.Roles),
	}
	user, err := m.keycloakClient.CreateUser(m.ctx, user)
	if err == keycloak.ErrUserConflict {
		return nil, ErrUserConflict
	}
	if err != nil {
		return nil, err
	}
	if err = m.keycloakClient.UpdateUserPassword(m.ctx, user.ID, *details.Password); err != nil {
		return nil, err
	}

	return NewUserFromKeycloakUser(user), nil
}

func (m *MigrationStore) UpsertUser(user *User) error {
	return m.fallback.UpsertUser(user)
}

func (m *MigrationStore) UpdateUser(user *User, details *UpdateUserDetails) (*User, error) {
	if user.IsMigrated {
		return m.updateKeycloakUser(user, details)
	}

	return m.fallback.UpdateUser(user, details)
}

func (m *MigrationStore) updateKeycloakUser(user *User, details *UpdateUserDetails) (*User, error) {
	keycloakUser := user.ToKeycloakUser()
	if details.Password != nil && len(*details.Password) > 0 {
		if err := m.keycloakClient.UpdateUserPassword(m.ctx, user.Id, *details.Password); err != nil {
			return nil, err
		}
		// A custodial user who's claiming their account
		if !IsValidEmail(user.Username) && !user.IsEnabled() {
			keycloakUser.Enabled = true
		}
	}
	if details.Emails != nil && len(details.Emails) > 0 {
		keycloakUser.Email = details.Emails[0]
	}
	if details.EmailVerified != nil {
		keycloakUser.EmailVerified = true
	}
	if details.TermsAccepted != nil && IsValidTimestamp(*details.TermsAccepted){
		if ts, err := TimestampToUnixString(*details.TermsAccepted); err != nil {
			keycloakUser.Attributes.TermsAcceptedDate = []string{ts}
		}
	}
	if details.Username != nil {
		keycloakUser.Username = *details.Username
	}

	err := m.keycloakClient.UpdateUser(m.ctx, keycloakUser)
	if err != nil {
		return nil, err
	}

	return NewUserFromKeycloakUser(keycloakUser), nil
}

func (m *MigrationStore) FindUser(user *User) (*User, error) {
	var keycloakUser *keycloak.User
	var err error

	if IsValidUserID(user.Id) {
		keycloakUser, err = m.keycloakClient.GetUserById(m.ctx, user.Id)
	} else {
		email := ""
		if user.Emails != nil && len(user.Emails) > 0 {
			email = user.Emails[0]
		}
		keycloakUser, err = m.keycloakClient.GetUserByEmail(m.ctx, email)
	}

	if err != nil && err != keycloak.ErrUserNotFound {
		return nil, err
	} else if err == nil && keycloakUser != nil {
		return NewUserFromKeycloakUser(keycloakUser), nil
	}

	// User was not found in keycloak, because it's not yet migrated
	users, err := m.fallback.FindUsers(user)
	if err != nil {
		return nil, err
	} else if count := len(users); count > 1 {
		return nil, errors.New(fmt.Sprintf("found %v users matching %v", len(users), user))
	} else if count == 0 || users[0] == nil {
		return nil, nil
	}

	return users[0], nil
}

func (m *MigrationStore) FindUsers(user *User) ([]*User, error) {
	return m.fallback.FindUsers(user)
}

func (m *MigrationStore) FindUsersByRole(role string) ([]*User, error) {
	return m.fallback.FindUsersByRole(role)
}

func (m *MigrationStore) FindUsersWithIds(ids []string) ([]*User, error) {
	return m.fallback.FindUsersWithIds(ids)
}

// Not used - deletions are handled by the user service
func (m *MigrationStore) RemoveUser(user *User) error {
	return m.fallback.RemoveUser(user)
}

func (m *MigrationStore) AddToken(token *SessionToken) error {
	return m.fallback.AddToken(token)
}

func (m *MigrationStore) FindTokenByID(id string) (*SessionToken, error) {
	return m.fallback.FindTokenByID(id)
}

func (m *MigrationStore) RemoveTokenByID(id string) error {
	return m.fallback.RemoveTokenByID(id)
}

var _ Storage = &MigrationStore{}
