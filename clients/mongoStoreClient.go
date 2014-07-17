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

func NewMongoStoreClient(config *mongo.Config) *MongoStoreClient {

	log.Println("creating client", config)

	//TODO - replace this with common version
	mongoSession, err := mgo.Dial("localhost")

	if err != nil {
		panic(err)
	}

	return &MongoStoreClient{
		session: mongoSession,
		usersC:  mongoSession.DB("shoreline").C(usersCollectionName),
		tokensC: mongoSession.DB("shoreline").C(tokensCollectionName),
	}
}

func (d MongoStoreClient) UpsertUser(user *api.User) error {

	if _, err := d.usersC.UpsertId(user.Id, user); err != nil {
		return err
	}

	return nil
}

func (d MongoStoreClient) GetUser(user *api.User) (result api.User, err error) {

	fieldsToMatch := []bson.M{}

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"_id": user.Id})
	}
	if user.Name != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"name": user.Name})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": user.Emails})
	}

	err = d.usersC.Find(bson.M{"$or": fieldsToMatch}).One(&result)
	if err != nil {
		return result, err
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
