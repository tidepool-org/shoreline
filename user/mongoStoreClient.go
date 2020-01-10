package user

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	tpMongo "github.com/tidepool-org/go-common/clients/mongo"
)

const (
	usersCollectionName  = "users"
	tokensCollectionName = "tokens"
	userStoreAPIPrefix   = "api/user/store"
)

// MongoStoreClient - Mongo Storage Client
type MongoStoreClient struct {
	client   *mongo.Client
	context  context.Context
	database string
}

// NewMongoStoreClient creates a new MongoStoreClient
func NewMongoStoreClient(config *tpMongo.Config) *MongoStoreClient {
	connectionString, err := config.ToConnectionString()
	if err != nil {
		log.Fatal(userStoreAPIPrefix, err)
	}

	clientOptions := options.Client().ApplyURI(connectionString)
	mongoClient, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(userStoreAPIPrefix, err)
	}

	return &MongoStoreClient{
		client:   mongoClient,
		context:  context.Background(),
		database: config.Database,
	}
}

// WithContext returns a shallow copy of c with its context changed
// to ctx. The provided ctx must be non-nil.
func (msc *MongoStoreClient) WithContext(ctx context.Context) *MongoStoreClient {
	if ctx == nil {
		panic("nil context")
	}
	msc2 := new(MongoStoreClient)
	*msc2 = *msc
	msc2.context = ctx
	return msc2
}

// EnsureIndexes - make sure indexes exist for the MongoDB collection
func (msc *MongoStoreClient) EnsureIndexes() error {
	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "userid", Value: 1}},
			Options: options.Index().
				SetBackground(true),
		},
		{
			Keys: bson.D{{Key: "username", Value: 1}},
			Options: options.Index().
				SetBackground(true),
		},
		{
			Keys: bson.D{{Key: "emails", Value: 1}},
			Options: options.Index().
				SetBackground(true),
		},
	}

	opts := options.CreateIndexes().SetMaxTime(10 * time.Second)

	if _, err := usersCollection(msc).Indexes().CreateMany(msc.context, indexes, opts); err != nil {
		log.Fatal(userStoreAPIPrefix, err)
	}

	return nil
}

func usersCollection(msc *MongoStoreClient) *mongo.Collection {
	return msc.client.Database(msc.database).Collection(usersCollectionName)
}

func tokensCollection(msc *MongoStoreClient) *mongo.Collection {
	return msc.client.Database(msc.database).Collection(tokensCollectionName)
}

// Ping the MongoDB database
func (msc *MongoStoreClient) Ping() error {
	// do we have a store session
	return msc.client.Ping(msc.context, nil)
}

// UpsertUser - Update an existing user's details, or insert a new user if the user doesn't already exist.
func (msc *MongoStoreClient) UpsertUser(user *User) error {
	if user.Roles != nil {
		sort.Strings(user.Roles)
	}

	// if the user already exists we update otherwise we add
	opts := options.FindOneAndUpdate().SetUpsert(true)
	result := usersCollection(msc).FindOneAndUpdate(msc.context, bson.M{"userid": user.Id}, user, opts)
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// FindUser - find and return an existing user
func (msc *MongoStoreClient) FindUser(user *User) (result *User, err error) {
	if user.Id != "" {
		if err = usersCollection(msc).FindOne(msc.context, bson.M{"userid": user.Id}).Decode(&result); err != nil {
			return result, err
		}
	}

	return result, nil
}

// FindUsers - find and return multiple existing users
func (msc *MongoStoreClient) FindUsers(user *User) (results []*User, err error) {
	fieldsToMatch := []bson.M{}
	const (
		MATCH = `^%s$`
	)

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"userid": user.Id})
	}
	if user.Username != "" {
		//case insensitive match
		// FIXME: should use an index with collation, not a case-insensitive regex, since that won't use an index
		fieldsToMatch = append(fieldsToMatch, bson.M{"username": bson.M{"$regex": primitive.Regex{fmt.Sprintf(MATCH, regexp.QuoteMeta(user.Username)), "i"}}})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": bson.M{"$in": user.Emails}})
	}

	if len(fieldsToMatch) == 0 {
		return []*User{}, nil
	}

	cursor, err := usersCollection(msc).Find(msc.context, bson.M{"$or": fieldsToMatch})
	if err != nil {
		return nil, err
	}

	if err = cursor.All(msc.context, &results); err != nil {
		return results, err
	}

	// TODO: does mongo-go-driver set results to nil?
	if results == nil {
		log.Printf("no users found: query: (Id = %v) OR (Name ~= %v) OR (Emails IN %v)", user.Id, user.Username, user.Emails)
		results = []*User{}
	}

	return results, nil
}

// FindUsersByRole - find and return multiple users matching a Role
func (msc *MongoStoreClient) FindUsersByRole(role string) (results []*User, err error) {
	cursor, err := usersCollection(msc).Find(msc.context, bson.M{"roles": role})
	if err != nil {
		return nil, err
	}

	if err = cursor.All(msc.context, &results); err != nil {
		return results, err
	}

	// TODO: does mongo-go-driver set results to nil?
	if results == nil {
		log.Printf("no users found: query: role: %v", role)
		results = []*User{}
	}

	return results, nil
}

// FindUsersWithIds - find and return multiple users by Tidepool User ID
func (msc *MongoStoreClient) FindUsersWithIds(ids []string) (results []*User, err error) {
	cursor, err := usersCollection(msc).Find(msc.context, bson.M{"userid": bson.M{"$in": ids}})
	if err != nil {
		return nil, err
	}

	if err = cursor.All(msc.context, &results); err != nil {
		return results, err
	}

	// TODO: does mongo-go-driver set results to nil?
	if results == nil {
		log.Printf("no users found: query: id: %v", ids)
		results = []*User{}
	}

	return results, nil
}

// RemoveUser - Remove a user from the database
func (msc *MongoStoreClient) RemoveUser(user *User) (err error) {
	result := usersCollection(msc).FindOneAndDelete(msc.context, bson.M{"userid": user.Id})
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// AddToken to the token collection
func (msc *MongoStoreClient) AddToken(st *SessionToken) error {
	// if the token already exists we update otherwise we add
	opts := options.FindOneAndUpdate().SetUpsert(true)
	result := tokensCollection(msc).FindOneAndUpdate(msc.context, bson.M{"_id": st.ID}, st, opts)
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}

	return nil
}

// FindTokenByID - find an auth token by its ID
func (msc *MongoStoreClient) FindTokenByID(id string) (*SessionToken, error) {
	sessionToken := &SessionToken{}
	if err := tokensCollection(msc).FindOne(msc.context, bson.M{"_id": id}).Decode(&sessionToken); err != nil {
		return nil, err
	}

	return sessionToken, nil
}

// RemoveTokenByID - delete an auth token matching an ID
func (msc *MongoStoreClient) RemoveTokenByID(id string) (err error) {
	result := tokensCollection(msc).FindOneAndDelete(msc.context, bson.M{"_id": id})
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}
