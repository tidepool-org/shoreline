package user

import (
	"context"
	"errors"
)

type MockStoreClient struct {
	salt            string
	doBad           bool
	returnDifferent bool
}

func NewMockStoreClient(salt string, returnDifferent, doBad bool) *MockStoreClient {
	return &MockStoreClient{salt: salt, doBad: doBad, returnDifferent: returnDifferent}
}

func (d *MockStoreClient) EnsureIndexes(ctx context.Context) error { return nil }

func (d MockStoreClient) Ping(ctx context.Context) error {
	if d.doBad {
		return errors.New("Session failure")
	}
	return nil
}

func (d MockStoreClient) Disconnect(ctx context.Context) error {
	return nil
}

func (d MockStoreClient) UpsertUser(ctx context.Context, user *User) error {
	if d.doBad {
		return errors.New("UpsertUser failure")
	}
	return nil
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
		found, err := NewUser(&NewUserDetails{Username: &user.Username, Password: &password, Emails: []string{}}, d.salt)
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
		other, err := NewUser(&NewUserDetails{Username: &username, Password: &password, Emails: []string{}}, d.salt)
		if err != nil {
			return nil, err
		}
		other.EmailVerified = true
		return other, nil
	}

	if user.Username != "" {
		found, err := NewUser(&NewUserDetails{Username: &user.Username, Password: &password, Emails: []string{}}, d.salt)
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

func (d MockStoreClient) AddToken(ctx context.Context, token *SessionToken) error {
	if d.doBad {
		return errors.New("AddToken failure")
	}
	return nil
}

func (d MockStoreClient) FindTokenByID(ctx context.Context, id string) (*SessionToken, error) {
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

func (d *MockStoreClient) RemoveTokensForUser(ctx context.Context, userId string) error {
	if d.doBad {
		return errors.New("RemoveTokensForUser failure")
	}
	return nil
}
