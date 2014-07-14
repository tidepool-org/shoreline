package clients

import (
	"tidepool.org/tide-whisperer/clients/mongo"
)

const (
	usersCollectionName  = "users"
	tokensCollectionName = "tokens"
)

type DataClient struct {
	session mongo.Session
}

func NewDataClient(config config.Mongo) *DataClient {

	mongoSession, err := mongo.Connect(config.Mongo)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	return &DataClient{session: mongoSession}
}

func (d DataClient) AddUser() {
	//d.session.DB("").C(usersCollectionName).
}

func (d DataClient) GetUser(userData) {

}

func (d DataClient) UpdateUser() {

}

func (d DataClient) RemoveUser() {

}

func (d DataClient) AddToken() {

}

func (d DataClient) UpdateToken() {

}

func (d DataClient) RemoveToken() {

}
