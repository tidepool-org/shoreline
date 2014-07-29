package clients

import (
	"crypto/rand"
	"github.com/tidepool-org/shoreline/models"
)

type MockStoreClient struct {
	salt string
}

func NewMockStoreClient(salt string) *MockStoreClient {
	return &MockStoreClient{salt: salt}
}

//faking the hashes
func rand_str(str_size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, str_size)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func (d MockStoreClient) UpsertUser(user *models.User) error {
	return nil
}

func (d MockStoreClient) FindUsers(user *models.User) (found []*models.User, err error) {
	//`find` a pretend one we just made
	if user.Id == "" && user.Pw != "" && user.Name != "" {
		found, _ := models.NewUser(user.Name, user.Pw, d.salt, []string{})
		return []*models.User{found}, nil
	}

	return []*models.User{user}, nil
}

func (d MockStoreClient) FindUser(user *models.User) (found *models.User, err error) {
	//`find` a pretend one we just made
	if user.Id == "" && user.Pw != "" && user.Name != "" {
		found, _ := models.NewUser(user.Name, user.Pw, d.salt, []string{})
		return found, nil
	}
	return user, nil
}

func (d MockStoreClient) RemoveUser(user *models.User) error {
	return nil
}

func (d MockStoreClient) AddToken(token *models.SessionToken) error {
	return nil
}

func (d MockStoreClient) FindToken(token *models.SessionToken) (*models.SessionToken, error) {
	//`find` a pretend one we just made
	return token, nil
}

func (d MockStoreClient) RemoveToken(token *models.SessionToken) error {
	return nil
}
