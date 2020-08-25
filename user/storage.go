package user

import (
	"context"
)

// Storage interface
type Storage interface {
	Ping() error
	WithContext(ctx context.Context) Storage
	EnsureIndexes() error
	CreateUser(details *NewUserDetails) (*User, error)
	UpdateUser(user *User, details *UpdateUserDetails) (*User, error)
	UpsertUser(user *User) error
	FindUser(user *User) (*User, error)
	FindUsers(user *User) ([]*User, error)
	FindUsersByRole(role string) ([]*User, error)
	FindUsersWithIds(role []string) ([]*User, error)
	RemoveUser(user *User) error
	AddToken(token *SessionToken) error
	FindTokenByID(id string) (*SessionToken, error)
	RemoveTokenByID(id string) error
}
