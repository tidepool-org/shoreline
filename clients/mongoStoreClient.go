package clients

import (
	"./../models"
	"fmt"
	"github.com/tidepool-org/go-common/clients/mongo"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"log"
)

const (
	USERS_COLLECTION  = "users"
	TOKENS_COLLECTION = "tokens"
)

type MongoStoreClient struct {
	session *mgo.Session
	usersC  *mgo.Collection
	tokensC *mgo.Collection
}

func NewMongoStoreClient(config *mongo.Config) *MongoStoreClient {

	mongoSession, err := mongo.Connect(config)
	if err != nil {
		log.Fatal(err)
	}

	return &MongoStoreClient{
		session: mongoSession,
		usersC:  mongoSession.DB("shoreline").C(USERS_COLLECTION),
		tokensC: mongoSession.DB("shoreline").C(TOKENS_COLLECTION),
	}
}

func (d MongoStoreClient) Close() {
	log.Println("Close the session")
	d.session.Close()
	return
}

func (d MongoStoreClient) Ping() error {
	// do we have a store session
	if err := d.session.Ping(); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) UpsertUser(user *models.User) error {

	// if the user already exists we update otherwise we add
	if _, err := d.usersC.Upsert(bson.M{"userid": user.Id}, user); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) FindUser(user *models.User) (result *models.User, err error) {

	if user.Id != "" {
		if err = d.usersC.Find(bson.M{"userid": user.Id}).One(&result); err != nil {
			return result, err
		}
	}

	return result, nil
}

func (d MongoStoreClient) FindUsers(user *models.User) (results []*models.User, err error) {

	fieldsToMatch := []bson.M{}
	const (
		MATCH = `^%s$`
	)

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"userid": user.Id})
	}
	if user.Name != "" {
		//case insensitive match
		fieldsToMatch = append(fieldsToMatch, bson.M{"name": bson.M{"$regex": bson.RegEx{fmt.Sprintf(MATCH, user.Name), "i"}}})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": bson.M{"$in": user.Emails}})
	}

	if err = d.usersC.Find(bson.M{"$or": fieldsToMatch}).All(&results); err != nil {
		return results, err
	}

	if results == nil {
		results = []*models.User{}
	}

	return results, nil
}

func (d MongoStoreClient) RemoveUser(user *models.User) (err error) {
	if err = d.usersC.Remove(bson.M{"userid": user.Id}); err != nil {
		return err
	}
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
	check := bson.M{"$or": []bson.M{bson.M{"id": st.Id}, bson.M{"_id": st.Id}}}

	if err = d.tokensC.Find(check).One(&result); err != nil {
		return result, err
	}
	return result, nil
}

func (d MongoStoreClient) RemoveToken(st *models.SessionToken) (err error) {
	//todo: safe mode ?? i.e. {w:1}
	check := bson.M{"$or": []bson.M{bson.M{"id": st.Id}, bson.M{"_id": st.Id}}}
	if err = d.tokensC.Remove(check); err != nil {
		return err
	}
	return nil
}
