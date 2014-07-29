package clients

import (
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/shoreline/models"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
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

func (d MongoStoreClient) UpsertUser(user *models.User) error {

	// if the user already exists we update otherwise we add

	if _, err := d.usersC.Upsert(bson.M{"id": user.Id}, user); err != nil {
		return err
	}

	return nil
}

func (d MongoStoreClient) FindUser(user *models.User) (result *models.User, err error) {

	if user.Id != "" {
		if err = d.usersC.Find(bson.M{"id": user.Id}).One(&result); err != nil {
			return result, err
		}
	}

	return result, nil
}

func (d MongoStoreClient) FindUsers(user *models.User) (results []*models.User, err error) {

	fieldsToMatch := []bson.M{}

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"id": user.Id})
	}
	if user.Name != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"name": user.Name})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": user.Emails})
	}

	if err = d.usersC.Find(bson.M{"$or": fieldsToMatch}).All(&results); err != nil {
		return results, err
	}

	return results, nil
}

func (d MongoStoreClient) RemoveUser(userId string) (err error) {
	return nil
}

func (d MongoStoreClient) AddToken(st *models.SessionToken) error {
	//todo: safe mode ?? i.e. {w:1}
	if err := d.tokensC.Insert(st); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) FindToken(st *models.SessionToken) (result *models.SessionToken, err error) {
	//todo: safe mode ?? i.e. {w:1}

	if err = d.tokensC.Find(bson.M{"token": st.Token}).One(&result); err != nil {
		return result, err
	}
	return result, nil
}

func (d MongoStoreClient) RemoveToken(st *models.SessionToken) (err error) {
	//todo: safe mode ?? i.e. {w:1}
	if err = d.tokensC.Remove(bson.M{"token": st.Token}); err != nil {
		return err
	}
	return nil
}
