package oauth2api

import (
	"log"

	"github.com/RangelReale/osin"
	"github.com/tidepool-org/go-common/clients/mongo"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
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

func NewOAuthStorage(config *mongo.Config) *OAuthStorage {

	mongoSession, err := mongo.Connect(config)
	if err != nil {
		log.Fatal(err)
	}

	//mongoSession.SetMode(mgo.Monotonic, true)

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
		log.Print("NewOAuthStorage EnsureIndex error")
		log.Fatal(idxErr)
	}
	return storage
}

func (s *OAuthStorage) Clone() osin.Storage {
	return s
}

func (s *OAuthStorage) Close() {
	log.Print("OAuthStorage.Close(): closing the connection")
	//s.session.Close()
	return
}

func (store *OAuthStorage) GetClient(id string) (osin.Client, error) {
	log.Printf("GetClient %s", id)
	cpy := store.session.Copy()
	defer cpy.Close()
	clients := cpy.DB(db_name).C(client_collection)
	client := &osin.DefaultClient{}
	err := clients.FindId(id).Select(selectFilter).One(client)
	return client, err
}

func (store *OAuthStorage) SetClient(id string, client osin.Client) error {
	cpy := store.session.Copy()
	defer cpy.Close()
	clients := cpy.DB(db_name).C(client_collection)

	//see https://github.com/RangelReale/osin/issues/40
	clientToSave := osin.DefaultClient{}
	clientToSave.CopyFrom(client)

	_, err := clients.UpsertId(id, clientToSave)
	return err
}

func (store *OAuthStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)

	//see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.Client.(*osin.DefaultClient)
	data.Client = nil

	log.Printf("auth to save %v", data.UserData)

	_, err := authorizations.UpsertId(data.Code, data)
	return err
}

func (store *OAuthStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)
	data := &osin.AuthorizeData{}
	err := authorizations.FindId(code).Select(selectFilter).One(data)

	//TODO: funky but works for now
	//see https://github.com/RangelReale/osin/issues/40
	clientM := data.UserData.(bson.M)
	data.Client = &osin.DefaultClient{
		Id:          clientM["id"].(string),
		RedirectUri: clientM["redirecturi"].(string),
		Secret:      clientM["secret"].(string),
	}
	data.UserData = nil

	return data, err
}

func (store *OAuthStorage) RemoveAuthorize(code string) error {
	cpy := store.session.Copy()
	defer cpy.Close()
	authorizations := cpy.DB(db_name).C(authorize_collection)
	return authorizations.RemoveId(code)
}

func (store *OAuthStorage) SaveAccess(data *osin.AccessData) error {
	cpy := store.session.Copy()
	defer cpy.Close()

	//see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.Client.(*osin.DefaultClient)
	data.Client = nil

	accesses := cpy.DB(db_name).C(access_collection)
	_, err := accesses.UpsertId(data.AccessToken, data)
	return err
}

func (store *OAuthStorage) LoadAccess(token string) (*osin.AccessData, error) {
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	data := &osin.AccessData{}
	err := accesses.FindId(token).Select(selectFilter).One(data)

	//TODO: funky but works for now
	//see https://github.com/RangelReale/osin/issues/40
	clientM := data.UserData.(bson.M)
	data.Client = &osin.DefaultClient{
		Id:          clientM["id"].(string),
		RedirectUri: clientM["redirecturi"].(string),
		Secret:      clientM["secret"].(string),
	}
	data.UserData = nil

	return data, err
}

func (store *OAuthStorage) RemoveAccess(token string) error {
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	return accesses.RemoveId(token)
}

func (store *OAuthStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	accData := new(osin.AccessData)
	err := accesses.Find(bson.M{refreshtoken: token}).Select(selectFilter).One(accData)
	return accData, err
}

func (store *OAuthStorage) RemoveRefresh(token string) error {
	cpy := store.session.Copy()
	defer cpy.Close()
	accesses := cpy.DB(db_name).C(access_collection)
	return accesses.Update(bson.M{refreshtoken: token}, bson.M{
		"$unset": bson.M{
			refreshtoken: 1,
		}})
}
