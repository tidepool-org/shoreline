package user

import "context"

// Storage interface
type Storage interface {
	Ping(ctx context.Context) error
	EnsureIndexes(ctx context.Context) error
	UpsertUser(ctx context.Context, user *User) error
	FindUser(ctx context.Context, user *User) (*User, error)
	FindUsers(ctx context.Context, user *User) ([]*User, error)
	FindUsersByRole(ctx context.Context, role string) ([]*User, error)
	FindUsersWithIds(ctx context.Context, role []string) ([]*User, error)
	RemoveUser(ctx context.Context, user *User) error
	AddToken(ctx context.Context, token *SessionToken) error
	FindTokenByID(ctx context.Context, id string) (*SessionToken, error)
	RemoveTokenByID(ctx context.Context, id string) error
	RemoveTokensForUser(ctx context.Context, userId string) error
}
