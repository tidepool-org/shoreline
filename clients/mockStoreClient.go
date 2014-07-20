package clients

import (
	models "github.com/tidepool-org/shoreline/models"
)

type MockStoreClient struct{}

func NewMockStoreClient() *MockStoreClient {
	return &MockStoreClient{}
}

func (d MockStoreClient) AddUser(user models.User) {
	//d.usersC
}

func (d MockStoreClient) GetUser(user models.User) {

}

func (d MockStoreClient) UpdateUser(user models.User) {

}

func (d MockStoreClient) RemoveUser(userId string) {

}

func (d MockStoreClient) AddToken(token models.SessionToken) {

}

func (d MockStoreClient) UpdateToken(token models.SessionToken) {

}

func (d MockStoreClient) RemoveToken(token models.SessionToken) {

}
