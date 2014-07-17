package clients

import (
	api "github.com/tidepool-org/shoreline/api"
)

type MockStoreClient struct{}

func NewMockStoreClient() *MockStoreClient {
	return &MockStoreClient{}
}

func (d MockStoreClient) AddUser(user api.User) {
	//d.usersC
}

func (d MockStoreClient) GetUser(user api.User) {

}

func (d MockStoreClient) UpdateUser(user api.User) {

}

func (d MockStoreClient) RemoveUser(userId string) {

}

func (d MockStoreClient) AddToken(token api.SessionToken) {

}

func (d MockStoreClient) UpdateToken(token api.SessionToken) {

}

func (d MockStoreClient) RemoveToken(token api.SessionToken) {

}
