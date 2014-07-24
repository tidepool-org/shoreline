package clients

import (
	"crypto/rand"
	"github.com/tidepool-org/shoreline/models"
)

type MockStoreClient struct{}

func NewMockStoreClient() *MockStoreClient {
	return &MockStoreClient{}
}

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

func (d MockStoreClient) FindUser(user *models.User) (found *models.User, err error) {
	//`find` a pretend one we just made
	found = &models.User{Id: rand_str(10), Name: user.Name, Emails: user.Emails, PwHash: rand_str(24), Hash: rand_str(24)}
	return found, nil
}

func (d MockStoreClient) RemoveUser(userId string) error {
	return nil
}

func (d MockStoreClient) AddToken(token *models.SessionToken) error {
	return nil
}

func (d MockStoreClient) FindToken(tokenId string) (*models.SessionToken, error) {
	//`find` a pretend one we just made
	token, _ := models.NewSessionToken(&models.Data{IsServer: true, Duration: 3600, UserId: "1234", Valid: true}, "my secret")
	return token, nil
}

func (d MockStoreClient) RemoveToken(tokenId string) error {
	return nil
}
