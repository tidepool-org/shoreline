package oauth2

import (
	"log"

	"github.com/RangelReale/osin"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"github.com/tidepool-org/go-common/clients/mongo"
)

type OAuthStorage struct {
	session *mgo.Session
}

const (
	//mongo collections
	client_collection    = "oauth_client"
	authorize_collection = "oauth_authorize"
	access_collection    = "oauth_access"
	db_name              = ""

	refreshtoken = "refreshtoken"
)

//filter used to exclude the mongo _id from being returned
var selectFilter = bson.M{"_id": 0}

//We implement the interface from osin.Storage
func NewOAuthStorage(config *mongo.Config) *OAuthStorage {

	mongoSession, err := mongo.Connect(config)
	if err != nil {
		log.Fatal(err)
	}

	storage := &OAuthStorage{session: mongoSession}

	index := mgo.Index{
		Key:        []string{refreshtoken},
		Unique:     false, // refreshtoken is sometimes empty
		DropDups:   false,
		Background: true,
		Sparse:     true,
	}

	accesses := storage.session.DB(db_name).C(access_collection)

	idxErr := accesses.EnsureIndex(index)
	if idxErr != nil {
		log.Printf(OAUTH2_API_PREFIX+"NewOAuthStorage EnsureIndex error[%s] ", idxErr.Error())
		log.Fatal(idxErr)
	}
	return storage
}

func getUserData(raw interface{}) (ud map[string]interface{}) {
	if raw != nil {
		userDataM := raw.(bson.M)
		return map[string]interface{}{"AppName": userDataM["AppName"], "AppUser": userDataM["AppUser"]}
	}
	log.Print(OAUTH2_API_PREFIX, "getUserData has no raw data to process")
	return map[string]interface{}{}
}

func getClient(raw interface{}) *osin.DefaultClient {

	log.Printf("getClient %v", raw)

	if raw != nil && raw.(bson.M) != nil {

		clientM := raw.(bson.M)

		return &osin.DefaultClient{
			Id:          clientM["id"].(string),
			RedirectUri: clientM["redirecturi"].(string),
			Secret:      clientM["secret"].(string),
			UserData:    getUserData(clientM["userdata"]),
		}
	}
	log.Print(OAUTH2_API_PREFIX, "getClient has no raw data to process")
	return &osin.DefaultClient{}
}

func (s *OAuthStorage) Clone() osin.Storage {
	return s
}

func (s *OAuthStorage) Close() {
	log.Print(OAUTH2_API_PREFIX, "OAuthStorage.Close(): closing the connection")
	//s.session.Close()
	return
}

func (store *OAuthStorage) GetClient(id string) (osin.Client, error) {
	log.Printf(OAUTH2_API_PREFIX+"GetClient id[%s]", id)
	cpy := store.session.Copy()
	defer cpy.Close()
	clients := cpy.DB(db_name).C(client_collection)
	client := &osin.DefaultClient{}
	if err := clients.Find(bson.M{"id": id}).Select(selectFilter).One(client); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"GetClient error[%s]", err.Error())
		return nil, err
	}
	log.Printf(OAUTH2_API_PREFIX+"GetClient found %v", client)
	client.UserData = getUserData(client.UserData)
	return client, nil
}

func (store *OAuthStorage) SetClient(id string, client osin.Client) error {
	cpy := store.session.Copy()
	defer cpy.Close()
	clients := cpy.DB(db_name).C(client_collection)

	//see https://github.com/RangelReale/osin/issues/40
	clientToSave := osin.DefaultClient{}
	clientToSave.CopyFrom(client)

	_, err := clients.Upsert(bson.M{"id": id}, clientToSave)
	return err
}

func (store *OAuthStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	log.Printf(OAUTH2_API_PREFIX+"SaveAuthorize for code[%s]", data.Code)
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)

	//see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.Client.(*osin.DefaultClient)
	data.Client = nil

	if _, err := authorizations.Upsert(bson.M{"code": data.Code}, data); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"SaveAuthorize error[%s]", err.Error())
		return err
	}
	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (store *OAuthStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	log.Printf(OAUTH2_API_PREFIX+"LoadAuthorize for code[%s]", code)
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)
	data := &osin.AuthorizeData{}

	if err := authorizations.Find(bson.M{"code": code}).Select(selectFilter).One(data); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"LoadAuthorize error[%s]", err.Error())
		return nil, err
	}

	log.Printf(OAUTH2_API_PREFIX+"LoadAuthorize found %v", data)

	//see https://github.com/RangelReale/osin/issues/40
	data.Client = getClient(data.UserData)

	return data, nil
}

func (store *OAuthStorage) RemoveAuthorize(code string) error {
	log.Printf(OAUTH2_API_PREFIX+"RemoveAuthorize for code[%s]", code)
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)
	return authorizations.Remove(bson.M{"code": code})
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (store *OAuthStorage) SaveAccess(data *osin.AccessData) error {
	log.Printf(OAUTH2_API_PREFIX+"SaveAccess for token[%s]", data.AccessToken)
	cpy := store.session.Copy()
	defer cpy.Close()

	// see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.AuthorizeData.UserData //Note: we want to save all the details that where set on Authorization
	data.Client = nil
	// see note on LoadAccess, but we don't bother persisting these
	data.AuthorizeData = nil
	data.AccessData = nil

	accesses := cpy.DB(db_name).C(access_collection)

	if _, err := accesses.Upsert(bson.M{"accesstoken": data.AccessToken}, data); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"SaveAccess error[%s]", err.Error())
	}

	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (store *OAuthStorage) LoadAccess(token string) (ad *osin.AccessData, err error) {
	log.Print(OAUTH2_API_PREFIX, "LoadAccess for token ", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)

	if err = accesses.Find(bson.M{"accesstoken": token}).Select(selectFilter).One(&ad); err != nil {
		log.Print(OAUTH2_API_PREFIX, "LoadAccess error ", err.Error())
		return nil, err
	}

	//see https://github.com/RangelReale/osin/issues/40
	ad.Client = getClient(ad.UserData)

	return ad, nil
}

func (store *OAuthStorage) RemoveAccess(token string) error {
	log.Printf(OAUTH2_API_PREFIX+"RemoveAccess for token[%s]", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	return accesses.Remove(bson.M{"accesstoken": token})
}

func (store *OAuthStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	log.Printf(OAUTH2_API_PREFIX+"LoadRefresh for token[%s]", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	data := new(osin.AccessData)

	if err := accesses.Find(bson.M{"refreshtoken": token}).Select(selectFilter).One(data); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"LoadRefresh error[%s]", err.Error())
		return nil, err
	}
	log.Printf(OAUTH2_API_PREFIX+"LoadRefresh found %v", data)
	return data, nil
}

func (store *OAuthStorage) RemoveRefresh(token string) error {
	log.Printf(OAUTH2_API_PREFIX+"RemoveRefresh for token[%s]", token)
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	return accesses.Update(bson.M{"refreshtoken": token}, bson.M{
		"$unset": bson.M{
			refreshtoken: 1,
		}})
}
