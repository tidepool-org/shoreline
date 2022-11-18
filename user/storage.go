package user

import (
	"context"

	goComMgo "github.com/mdblp/go-db/mongo"
	"github.com/mdblp/shoreline/token"
)

type Storage interface {
	goComMgo.Storage
	UpsertUser(ctx context.Context, user *User) error
	FindUser(ctx context.Context, user *User) (*User, error)
	ExistDirtyUser(ctx context.Context, username string) bool
	FindUsers(ctx context.Context, user *User) ([]*User, error)
	FindUsersByRole(ctx context.Context, role string) ([]*User, error)
	FindUsersByEmailVerified(ctx context.Context, auth bool) ([]*User, error)
	FindUsersWithIds(ctx context.Context, role []string) ([]*User, error)
	RemoveUser(ctx context.Context, user *User) error
	AddToken(ctx context.Context, token *token.SessionToken) error
	FindTokenByID(ctx context.Context, id string) (*token.SessionToken, error)
	RemoveTokenByID(ctx context.Context, id string) error
}
