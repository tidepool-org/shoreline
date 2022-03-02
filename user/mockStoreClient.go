package user

import (
	"context"
	"errors"

	"github.com/mdblp/shoreline/token"
	"go.mongodb.org/mongo-driver/mongo"
)

type MockStoreClient struct {
	salt            string
	doBad           bool
	returnDifferent bool
}

func NewMockStoreClient(salt string, returnDifferent, doBad bool) *MockStoreClient {
	return &MockStoreClient{salt: salt, doBad: doBad, returnDifferent: returnDifferent}
}

func (d *MockStoreClient) Close() error {
	return nil
}
func (d MockStoreClient) Ping() error {
	if d.doBad {
		return errors.New("session failure")
	}
	return nil
}
func (d *MockStoreClient) PingOK() bool {
	return !d.doBad
}
func (d *MockStoreClient) Collection(collectionName string, databaseName ...string) *mongo.Collection {
	return nil
}
func (d *MockStoreClient) WaitUntilStarted() {}
func (d *MockStoreClient) Start()            {}

func (d MockStoreClient) UpsertUser(ctx context.Context, user *User) error {
	if d.doBad {
		return errors.New("UpsertUser failure")
	}
	return nil
}

func (d MockStoreClient) ExistDirtyUser(ctx context.Context, username string) (res bool) {
	if username == "dirtyUser" {
		return true
	}
	return false
}

func (d MockStoreClient) FindUsers(ctx context.Context, user *User) (found []*User, err error) {
	//`find` a pretend one we just made

	if d.doBad {
		return found, errors.New("FindUsers failure")
	}

	password := "123youknoWm3"

	if d.returnDifferent {
		return []*User{}, nil
	}

	if user.Username != "" {
		found, err := NewUser(&NewUserDetails{Username: &user.Username, Password: &password, Emails: []string{}}, d.salt, "public")
		if err != nil {
			return []*User{}, err
		}
		found.EmailVerified = true

		return []*User{found}, nil
	}
	user.EmailVerified = true

	return []*User{user}, nil

}

func (d MockStoreClient) FindUsersByRole(ctx context.Context, role string) (found []*User, err error) {
	if d.doBad {
		return found, errors.New("FindUsersByRole failure")
	}
	return nil, nil
}

func (d MockStoreClient) FindUsersByEmailVerified(ctx context.Context, auth bool) (found []*User, err error) {
	if d.doBad {
		return found, errors.New("FindUsersByEmailVerified failure")
	}
	return nil, nil
}

func (d MockStoreClient) FindUsersWithIds(ctx context.Context, ids []string) (found []*User, err error) {
	if d.doBad {
		return found, errors.New("FindUsersWithIds failure")
	}
	var users []*User

	// Create a pair of users to test with
	usernameOne := "userOne@b.co"
	usernameTwo := "userTwo@b.co"

	for _, id := range ids {
		switch id {
		case "0000000000":
			users = append(users, &User{Id: "0000000000", Username: usernameOne, Emails: []string{usernameOne}})
		case "0000000001":
			users = append(users, &User{Id: "0000000001", Username: usernameTwo, Emails: []string{usernameTwo}})
		}
	}

	return users, nil
}

func (d MockStoreClient) FindUser(ctx context.Context, user *User) (found *User, err error) {

	if d.doBad {
		return found, errors.New("FindUser failure")
	}
	//`find` a pretend one we just made

	username := "a@b.co"
	password := "123youknoWm3"

	if d.returnDifferent {
		other, err := NewUser(&NewUserDetails{Username: &username, Password: &password, Emails: []string{}}, d.salt, "public")
		if err != nil {
			return nil, err
		}
		other.EmailVerified = true
		return other, nil
	}

	if user.Username != "" {
		found, err := NewUser(&NewUserDetails{Username: &user.Username, Password: &password, Emails: []string{}}, d.salt, "public")
		if err != nil {
			return nil, err
		}
		found.EmailVerified = true
		return found, nil
	}
	user.EmailVerified = true
	return user, nil
}

func (d MockStoreClient) RemoveUser(ctx context.Context, user *User) error {
	if d.doBad {
		return errors.New("RemoveUser failure")
	}
	return nil
}

func (d MockStoreClient) AddToken(ctx context.Context, token *token.SessionToken) error {
	if d.doBad {
		return errors.New("AddToken failure")
	}
	return nil
}

func (d MockStoreClient) FindTokenByID(ctx context.Context, id string) (*token.SessionToken, error) {
	if d.doBad {
		return nil, errors.New("FindTokenByID failure")
	}
	//`find` a pretend one we just made
	return nil, nil
}

func (d MockStoreClient) RemoveTokenByID(ctx context.Context, id string) error {
	if d.doBad {
		return errors.New("RemoveTokenByID failure")
	}
	return nil
}
