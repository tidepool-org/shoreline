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

	log.Printf("found: %v", result)

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

	log.Printf("looking for ... [%v] ", fieldsToMatch)

	if err = d.usersC.Find(bson.M{"$or": fieldsToMatch}).All(&results); err != nil {
		return results, err
	}

	if results == nil {
		log.Print("no users found ")
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
	//map to the structure we want to save to mongo as
	token := bson.M{"_id": st.Id, "time": st.Time}

	if err := d.tokensC.Insert(token); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) FindToken(st *models.SessionToken) (*models.SessionToken, error) {

	var result map[string]interface{}
	if err := d.tokensC.Find(bson.M{"_id": st.Id}).One(&result); err != nil {
		return nil, err
	}
	//map to the token structure the service uses
	tkn := &models.SessionToken{Id: result["_id"].(string), Time: result["time"].(int64)}

	return tkn, nil
}

func (d MongoStoreClient) RemoveToken(st *models.SessionToken) (err error) {
	if err = d.tokensC.Remove(bson.M{"_id": st.Id}); err != nil {
		return err
	}
	return nil
}
