package clients

import (
	models "github.com/tidepool-org/shoreline/models"
	"time"
)

type MockStoreClient struct{}

func NewMockStoreClient() *MockStoreClient {
	return &MockStoreClient{}
}

func (d MockStoreClient) UpsertUser(user *models.User) error {
	return nil
}

func (d MockStoreClient) FindUser(user *models.User) (*models.User, error) {
	return user, nil
}

func (d MockStoreClient) RemoveUser(userId string) error {
	return nil
}

func (d MockStoreClient) AddToken(token *models.SessionToken) error {
	return nil
}

func (d MockStoreClient) FindToken(tokenId string) (*models.SessionToken, error) {
	return &models.SessionToken{Token: tokenId, Time: time.Now().String()}, nil
}

func (d MockStoreClient) RemoveToken(tokenId string) error {
	return nil
}
