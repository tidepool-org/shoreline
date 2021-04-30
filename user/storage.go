package user

import (
	"context"
	"time"
)

// Storage interface
type Storage interface {
	Ping() error
	WithContext(ctx context.Context) Storage
	EnsureIndexes() error
	UpsertUser(user *User) error
	FindUser(user *User) (*User, error)
	FindUsers(user *User) ([]*User, error)
	FindUsersByRole(role string) ([]*User, error)
	FindUsersByRoleAndDate(role string, from time.Time, to time.Time) ([]*User, error)
	FindUsersWithIds(role []string) ([]*User, error)
	RemoveUser(user *User) error
	AddToken(token *SessionToken) error
	FindTokenByID(id string) (*SessionToken, error)
	RemoveTokenByID(id string) error
	RemoveTokensForUser(userId string) error
}
