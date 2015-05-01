package user

import (
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
}

//We implement the interface from user.Storage
func NewMongoStoreClient(config *mongo.Config) *MongoStoreClient {

	mongoSession, err := mongo.Connect(config)
	if err != nil {
		log.Fatal(err)
	}

	return &MongoStoreClient{
		session: mongoSession,
	}
}

func mgoUsersCollection(cpy *mgo.Session) *mgo.Collection {
	return cpy.DB("").C(USERS_COLLECTION)
}

func mgoTokensCollection(cpy *mgo.Session) *mgo.Collection {
	return cpy.DB("").C(TOKENS_COLLECTION)
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

func (d MongoStoreClient) UpsertUser(user *User) error {

	cpy := d.session.Copy()
	defer cpy.Close()

	// if the user already exists we update otherwise we add
	if _, err := mgoUsersCollection(cpy).Upsert(bson.M{"userid": user.Id}, user); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) FindUser(user *User) (result *User, err error) {

	if user.Id != "" {
		cpy := d.session.Copy()
		defer cpy.Close()

		if err = mgoUsersCollection(cpy).Find(bson.M{"userid": user.Id}).One(&result); err != nil {
			return result, err
		}
	}

	return result, nil
}

func (d MongoStoreClient) FindUsers(user *User) (results []*User, err error) {

	fieldsToMatch := []bson.M{}
	const (
		MATCH = `^%s$`
	)

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"userid": user.Id})
	}
	if user.Name != "" {
		//case insensitive match
		fieldsToMatch = append(fieldsToMatch, bson.M{"username": bson.M{"$regex": bson.RegEx{fmt.Sprintf(MATCH, user.Name), "i"}}})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": bson.M{"$in": user.Emails}})
	}

	cpy := d.session.Copy()
	defer cpy.Close()

	if err = mgoUsersCollection(cpy).Find(bson.M{"$or": fieldsToMatch}).All(&results); err != nil {
		return results, err
	}

	if results == nil {
		log.Print("no users found ")
		results = []*User{}
	}

	return results, nil
}

func (d MongoStoreClient) RemoveUser(user *User) (err error) {
	cpy := d.session.Copy()
	defer cpy.Close()

	if err = mgoUsersCollection(cpy).Remove(bson.M{"userid": user.Id}); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) AddToken(st *SessionToken) error {
	//map to the structure we want to save to mongo as
	token := bson.M{"_id": st.Id, "time": st.Time}
	cpy := d.session.Copy()
	defer cpy.Close()

	if _, err := mgoTokensCollection(cpy).Upsert(bson.M{"_id": st.Id}, token); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) FindToken(st *SessionToken) (*SessionToken, error) {

	var result map[string]interface{}
	cpy := d.session.Copy()
	defer cpy.Close()

	if err := mgoTokensCollection(cpy).Find(bson.M{"_id": st.Id}).One(&result); err != nil {
		return nil, err
	}
	//map to the token structure the service uses
	tkn := &SessionToken{Id: result["_id"].(string), Time: result["time"].(int64)}

	return tkn, nil
}

func (d MongoStoreClient) RemoveToken(st *SessionToken) (err error) {

	cpy := d.session.Copy()
	defer cpy.Close()

	if err = mgoTokensCollection(cpy).Remove(bson.M{"_id": st.Id}); err != nil {
		return err
	}
	return nil
}
