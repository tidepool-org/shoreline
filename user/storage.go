package user

import (
	"context"

	"github.com/mdblp/shoreline/token"
	goComMgo "github.com/tidepool-org/go-common/clients/mongo"
)

type Storage interface {
	goComMgo.Storage
	UpsertUser(ctx context.Context, user *User) error
	FindUser(ctx context.Context, user *User) (*User, error)
	FindUsers(ctx context.Context, user *User) ([]*User, error)
	FindUsersByRole(ctx context.Context, role string) ([]*User, error)
	FindUsersWithIds(ctx context.Context, role []string) ([]*User, error)
	RemoveUser(ctx context.Context, user *User) error
	AddToken(ctx context.Context, token *token.SessionToken) error
	FindTokenByID(ctx context.Context, id string) (*token.SessionToken, error)
	RemoveTokenByID(ctx context.Context, id string) error
}
