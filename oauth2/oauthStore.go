package oauth2

import (
	"context"
	"log"
	"time"

	"github.com/RangelReale/osin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	tpMongo "github.com/tidepool-org/go-common/clients/mongo"
)

// OAuthStorage - Mongo Storage Client
type OAuthStorage struct {
	client   *mongo.Client
	context  context.Context
	database string
}

const (
	//mongo collections
	clientCollection    = "oauth_client"
	authorizeCollection = "oauth_authorize"
	accessCollection    = "oauth_access"

	refreshToken = "refreshtoken"
)

//filter used to exclude the mongo _id from being returned
var selectFilter = bson.M{"_id": 0}

// NewOAuthStorage creates a new OAuthStorage. We implement the interface from osin.Storage
func NewOAuthStorage(config *tpMongo.Config) *OAuthStorage {
	connectionString, err := config.ToConnectionString()
	if err != nil {
		log.Fatal(err)
	}

	clientOptions := options.Client().ApplyURI(connectionString)
	mongoClient, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	storage := &OAuthStorage{
		client:   mongoClient,
		context:  context.Background(),
		database: config.Database,
	}

	return storage
}

// WithContext returns a shallow copy of c with its context changed
// to ctx. The provided ctx must be non-nil.
func (s *OAuthStorage) WithContext(ctx context.Context) *OAuthStorage {
	if ctx == nil {
		panic("nil context")
	}
	s2 := new(OAuthStorage)
	*s2 = *s
	s2.context = ctx
	return s2
}

// EnsureIndexes - make sure indexes exist for the MongoDB collection
func (s *OAuthStorage) EnsureIndexes() error {
	index := mongo.IndexModel{
		Keys: bson.D{{Key: refreshToken, Value: 1}},
		Options: options.Index().
			SetBackground(true).
			SetSparse(true),
	}

	accesses := s.client.Database(s.database).Collection(accessCollection)

	opts := options.CreateIndexes().SetMaxTime(10 * time.Second)

	if _, err := accesses.Indexes().CreateOne(s.context, index, opts); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"NewOAuthStorage EnsureIndex error[%s] ", err.Error())
		log.Fatal(err)
	}

	return nil
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

// Clone the OAuthStorage
func (s *OAuthStorage) Clone() osin.Storage {
	return s
}

// Close the OAuthStorage
func (s *OAuthStorage) Close() {
	log.Print(OAUTH2_API_PREFIX, "OAuthStorage.Close(): closing the connection")
	return
}

// GetClient with a specific id
func (s *OAuthStorage) GetClient(id string) (osin.Client, error) {
	log.Printf(OAUTH2_API_PREFIX+"GetClient id[%s]", id)
	clients := s.client.Database(s.database).Collection(clientCollection)

	client := &osin.DefaultClient{}
	opts := options.FindOne().SetProjection(selectFilter)
	if err := clients.FindOne(s.context, bson.M{"id": id}, opts).Decode(client); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"GetClient error[%s]", err.Error())
		return nil, err
	}
	log.Printf(OAUTH2_API_PREFIX+"GetClient found %v", client)
	client.UserData = getUserData(client.UserData)
	return client, nil
}

// SetClient - update the client data for a Client ID, or insert it if it doesn't exist.
func (s *OAuthStorage) SetClient(id string, client osin.Client) error {
	log.Printf(OAUTH2_API_PREFIX+"SetClient %v", client)
	clients := s.client.Database(s.database).Collection(clientCollection)

	//see https://github.com/RangelReale/osin/issues/40
	clientToSave := osin.DefaultClient{}
	clientToSave.CopyFrom(client)

	opts := options.FindOneAndUpdate().SetUpsert(true)
	result := clients.FindOneAndUpdate(s.context, bson.M{"id": id}, clientToSave, opts)
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// SaveAuthorize updates the AuthorizeData, or inserts if if it doesn't exist.
func (s *OAuthStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	log.Printf(OAUTH2_API_PREFIX+"SaveAuthorize for code[%s]", data.Code)
	authorizations := s.client.Database(s.database).Collection(authorizeCollection)

	//see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.Client.(*osin.DefaultClient)
	data.Client = nil

	opts := options.FindOneAndUpdate().SetUpsert(true)
	result := authorizations.FindOneAndUpdate(s.context, bson.M{"code": data.Code}, data, opts)
	if result.Err() != mongo.ErrNoDocuments {
		log.Printf(OAUTH2_API_PREFIX+"SaveAuthorize error[%s]", result.Err())
		return result.Err()
	}
	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *OAuthStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	log.Printf(OAUTH2_API_PREFIX+"LoadAuthorize for code[%s]", code)
	authorizations := s.client.Database(s.database).Collection(authorizeCollection)
	data := &osin.AuthorizeData{}

	opts := options.FindOne().SetProjection(selectFilter)
	if err := authorizations.FindOne(s.context, bson.M{"code": code}, opts).Decode(data); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"LoadAuthorize error[%s]", err.Error())
		return nil, err
	}

	log.Printf(OAUTH2_API_PREFIX+"LoadAuthorize found %v", data)

	//see https://github.com/RangelReale/osin/issues/40
	data.Client = getClient(data.UserData)

	return data, nil
}

// RemoveAuthorize removes an AuthorizeData by a code.
func (s *OAuthStorage) RemoveAuthorize(code string) error {
	log.Printf(OAUTH2_API_PREFIX+"RemoveAuthorize for code[%s]", code)
	authorizations := s.client.Database(s.database).Collection(authorizeCollection)
	result := authorizations.FindOneAndDelete(s.context, bson.M{"code": code})
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *OAuthStorage) SaveAccess(data *osin.AccessData) error {
	log.Printf(OAUTH2_API_PREFIX+"SaveAccess for token[%s]", data.AccessToken)

	// see https://github.com/RangelReale/osin/issues/40
	data.UserData = data.AuthorizeData.UserData //Note: we want to save all the details that where set on Authorization
	data.Client = nil
	// see note on LoadAccess, but we don't bother persisting these
	data.AuthorizeData = nil
	data.AccessData = nil

	accesses := s.client.Database(s.database).Collection(accessCollection)

	opts := options.FindOneAndUpdate().SetUpsert(true)
	result := accesses.FindOneAndUpdate(s.context, bson.M{"accesstoken": data.AccessToken}, data, opts)
	if result.Err() != mongo.ErrNoDocuments {
		log.Printf(OAUTH2_API_PREFIX+"SaveAccess error[%s]", result.Err())
		return result.Err()
	}
	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *OAuthStorage) LoadAccess(token string) (ad *osin.AccessData, err error) {
	log.Print(OAUTH2_API_PREFIX, "LoadAccess for token ", token)
	accesses := s.client.Database(s.database).Collection(accessCollection)

	opts := options.FindOne().SetProjection(selectFilter)
	if err = accesses.FindOne(s.context, bson.M{"accesstoken": token}, opts).Decode(&ad); err != nil {
		log.Print(OAUTH2_API_PREFIX, "LoadAccess error ", err.Error())
		return nil, err
	}

	//see https://github.com/RangelReale/osin/issues/40
	ad.Client = getClient(ad.UserData)

	return ad, nil
}

// RemoveAccess removes access data by token.
func (s *OAuthStorage) RemoveAccess(token string) error {
	log.Printf(OAUTH2_API_PREFIX+"RemoveAccess for token[%s]", token)
	accesses := s.client.Database(s.database).Collection(accessCollection)
	result := accesses.FindOneAndDelete(s.context, bson.M{"accesstoken": token})
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// LoadRefresh token data
func (s *OAuthStorage) LoadRefresh(token string) (*osin.AccessData, error) {
	log.Printf(OAUTH2_API_PREFIX+"LoadRefresh for token[%s]", token)
	accesses := s.client.Database(s.database).Collection(accessCollection)
	data := new(osin.AccessData)

	opts := options.FindOne().SetProjection(selectFilter)
	if err := accesses.FindOne(s.context, bson.M{"refreshtoken": token}, opts).Decode(data); err != nil {
		log.Printf(OAUTH2_API_PREFIX+"LoadRefresh error[%s]", err.Error())
		return nil, err
	}
	log.Printf(OAUTH2_API_PREFIX+"LoadRefresh found %v", data)
	return data, nil
}

// RemoveRefresh token data
func (s *OAuthStorage) RemoveRefresh(token string) error {
	log.Printf(OAUTH2_API_PREFIX+"RemoveRefresh for token[%s]", token)
	accesses := s.client.Database(s.database).Collection(accessCollection)
	data := bson.M{
		"$unset": bson.M{
			refreshToken: 1,
		}}
	result := accesses.FindOneAndUpdate(s.context, bson.M{"accesstoken": token}, data)
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}
