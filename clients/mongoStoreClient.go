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

	// if the user already exists we update otherwise we add
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

	if err = d.usersC.Find(bson.M{"$or": fieldsToMatch}).One(&result); err != nil {
		return result, err
	}

	/*TODO
	- pw check
	- return multiple of there are more than on mactch - e.g. on email
	*/

	/*if len(results) == 1 {
		if user.password {
			results[0].pwhash != user.HashPassword()
		}
	}*/

	// one thing found, so check if pw was specified
	/*if (userdata.password) {
	  if (items[0].pwhash !== hashpw(items[0].userid, userdata.password)) {
	    // there was a pw and it didn't match
	    done(null, { statuscode: 204, msg: 'User not found', detail: userdata.user });
	    return;
	  }
	}*/
	return result, nil
}

func (d MongoStoreClient) RemoveUser(userId string) {

}

func (d MongoStoreClient) AddToken(st *api.SessionToken) error {
	//todo: safe mode ?? i.e. {w:1}
	if err := d.tokensC.Insert(st); err != nil {
		return err
	}
	return nil
}

func (d MongoStoreClient) FindToken(token string) (result *api.SessionToken, err error) {
	//todo: safe mode ?? i.e. {w:1}
	if err = d.tokensC.Find(bson.M{"_id": token}).One(&result); err != nil {
		return result, err
	}
	return result, nil
}

func (d MongoStoreClient) RemoveToken(token string) (err error) {
	//todo: safe mode ?? i.e. {w:1}
	if err = d.tokensC.RemoveId(token); err != nil {
		return err
	}
	return nil
}
