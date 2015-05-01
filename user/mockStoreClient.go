package user

import (
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

func (d MockStoreClient) Close() {}

func (d MockStoreClient) Ping() error {
	if d.doBad {
		return errors.New("Session failure")
	}
	return nil
}

func (d MockStoreClient) UpsertUser(user *User) error {
	if d.doBad {
		return errors.New("UpsertUser failure")
	}
	return nil
}

func (d MockStoreClient) FindUsers(user *User) (found []*User, err error) {
	//`find` a pretend one we just made

	if d.doBad {
		return found, errors.New("FindUsers failure")
	}

	if d.returnDifferent {
		return []*User{}, nil
	}

	if user.Name != "" {
		found, _ := NewUser(&UserDetail{Name: user.Name, Pw: "123youknoWm3", Emails: []string{}}, d.salt)
		found.Verified = true

		return []*User{found}, nil
	}
	user.Verified = true

	return []*User{user}, nil

}

func (d MockStoreClient) FindUser(user *User) (found *User, err error) {

	if d.doBad {
		return found, errors.New("FindUser failure")
	}
	//`find` a pretend one we just made

	if d.returnDifferent {
		other, _ := NewUser(&UserDetail{Name: "Some One Else", Pw: "123youknoWm3", Emails: []string{}}, d.salt)
		other.Verified = true
		return other, nil
	}

	if user.Name != "" {
		found, _ := NewUser(&UserDetail{Name: user.Name, Pw: "123youknoWm3", Emails: []string{}}, d.salt)
		found.Verified = true
		return found, nil
	}
	user.Verified = true
	return user, nil
}

func (d MockStoreClient) RemoveUser(user *User) error {
	if d.doBad {
		return errors.New("RemoveUser failure")
	}
	return nil
}

func (d MockStoreClient) AddToken(token *SessionToken) error {
	if d.doBad {
		return errors.New("AddToken failure")
	}
	return nil
}

func (d MockStoreClient) FindToken(token *SessionToken) (*SessionToken, error) {
	if d.doBad {
		return token, errors.New("FindToken failure")
	}
	//`find` a pretend one we just made
	return token, nil
}

func (d MockStoreClient) RemoveToken(token *SessionToken) error {
	if d.doBad {
		return errors.New("RemoveToken failure")
	}
	return nil
}
