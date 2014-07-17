package clients

import (
	mongo "github.com/tidepool-org/go-common/clients/mongo"
	api "github.com/tidepool-org/shoreline/api"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"log"
)

const (
	usersCollectionName  = "users"
	tokensCollectionName = "tokens"
)

type MongoStoreClient struct {
	session *mgo.Session
	usersC  *mgo.Collection
	tokensC *mgo.Collection
}

func NewStoreClient(config *mongo.Config) *MongoStoreClient {

	mongoSession, err := mongo.Connect(config)
	if err != nil {
		log.Fatal(err)
	}
	defer mongoSession.Close()

	return &MongoStoreClient{session: mongoSession,
		usersC:  mongoSession.DB("").C(usersCollectionName),
		tokensC: mongoSession.DB("").C(tokensCollectionName),
	}
}

func (d MongoStoreClient) UpsertUser(user *api.User) error {

	if _, err := d.usersC.UpsertId(user.Id, &user); err != nil {
		panic(err)
	}
	return nil
}

func (d MongoStoreClient) GetUser(user *api.User) (result api.User, err error) {

	query := bson.M{
		"$or": bson.M{
			"id":     user.Id,
			"name":   user.Name,
			"emails": user.Emails,
		},
	}

	err = d.usersC.Find(query).One(&result)
	if err != nil {
		panic(err)
	}
	return result, nil

}

func (d MongoStoreClient) RemoveUser(userId string) {

}

func (d MongoStoreClient) AddToken(token *api.SessionToken) {
	//d.tokensC
}

func (d MongoStoreClient) UpdateToken(token *api.SessionToken) {

}

func (d MongoStoreClient) RemoveToken(token *api.SessionToken) {

}
