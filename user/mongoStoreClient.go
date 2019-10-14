package user

import (
	"fmt"
	"log"
	"regexp"
	"sort"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"

	"github.com/tidepool-org/go-common/clients/mongo"
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
		log.Fatalf("Cannot connect to mongo: %v, %v", config, err)
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
	log.Print(USER_API_PREFIX, "Close the session")
	d.session.Close()
	return
}

func (d MongoStoreClient) Ping() error {
	// do we have a store session
	cpy := d.session.Copy()
	defer cpy.Close()

	if err := cpy.Ping(); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) UpsertUser(user *User) error {

	cpy := d.session.Copy()
	defer cpy.Close()

	if user.Roles != nil {
		sort.Strings(user.Roles)
	}

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
	if user.Username != "" {
		//case insensitive match
		fieldsToMatch = append(fieldsToMatch, bson.M{"username": bson.M{"$regex": bson.RegEx{fmt.Sprintf(MATCH, regexp.QuoteMeta(user.Username)), "i"}}})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": bson.M{"$in": user.Emails}})
	}

	if len(fieldsToMatch) == 0 {
		return []*User{}, nil
	}

	cpy := d.session.Copy()
	defer cpy.Close()

	if err = mgoUsersCollection(cpy).Find(bson.M{"$or": fieldsToMatch}).All(&results); err != nil {
		return results, err
	}

	if results == nil {
		log.Printf("no users found: query: (Id = %v) OR (Name ~= %v) OR (Emails IN %v)", user.Id, user.Username, user.Emails)
		results = []*User{}
	}

	return results, nil
}

func (d MongoStoreClient) FindUsersByRole(role string) (results []*User, err error) {
	cpy := d.session.Copy()
	defer cpy.Close()

	if err = mgoUsersCollection(cpy).Find(bson.M{"roles": role}).All(&results); err != nil {
		return results, err
	}

	if results == nil {
		log.Printf("no users found: query: role: %v", role)
		results = []*User{}
	}

	return results, nil
}

func (d MongoStoreClient) FindUsersWithIds(ids []string) (results []*User, err error) {
	cpy := d.session.Copy()
	defer cpy.Close()

	if err = mgoUsersCollection(cpy).Find(bson.M{"userid": bson.M{"$in": ids}}).All(&results); err != nil {
		return results, err
	}

	if results == nil {
		log.Printf("no users found: query: id: %v", ids)
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
	cpy := d.session.Copy()
	defer cpy.Close()

	if _, err := mgoTokensCollection(cpy).Upsert(bson.M{"_id": st.ID}, st); err != nil {
		return err
	}

	return nil
}

func (d MongoStoreClient) FindTokenByID(id string) (*SessionToken, error) {
	cpy := d.session.Copy()
	defer cpy.Close()

	sessionToken := &SessionToken{}
	if err := mgoTokensCollection(cpy).Find(bson.M{"_id": id}).One(&sessionToken); err != nil {
		return nil, err
	}

	return sessionToken, nil
}

func (d MongoStoreClient) RemoveTokenByID(id string) (err error) {
	cpy := d.session.Copy()
	defer cpy.Close()

	if err = mgoTokensCollection(cpy).Remove(bson.M{"_id": id}); err != nil {
		return err
	}

	return nil
}
