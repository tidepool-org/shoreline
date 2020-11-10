package user

import (
	"context"
	"fmt"
	"log"
	"sort"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo"

	tpMongo "github.com/tidepool-org/go-common/clients/mongo"
)

const (
	usersCollectionName  = "users"
	tokensCollectionName = "tokens"
	userStoreAPIPrefix   = "api/user/store "
)

// Because the `users` collection already exists on all environments (especially `prd`),
// and MongoDB doesn't allow modification of default collation on an existing collection,
// we need to specify collation manually everywhere we generate an index, or make a query
// with the notable exception of the `_id` field
var usersCollation *options.Collation = &options.Collation{Locale: "en", Strength: 1}

// MongoStoreClient - Mongo Storage Client
type MongoStoreClient struct {
	client   *mongo.Client
	database string
}

// NewMongoStoreClient creates a new MongoStoreClient
func NewMongoStoreClient(config *tpMongo.Config) *MongoStoreClient {
	connectionString, err := config.ToConnectionString()
	if err != nil {
		log.Fatal(userStoreAPIPrefix, fmt.Sprintf("Invalid MongoDB configuration: %s", err))
	}

	clientOptions := options.Client().ApplyURI(connectionString)
	clientOptions.Monitor = otelmongo.NewMonitor("shoreline")
	mongoClient, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(userStoreAPIPrefix, fmt.Sprintf("Invalid MongoDB connection string: %s", err))
	}

	return &MongoStoreClient{
		client:   mongoClient,
		database: config.Database,
	}
}

// EnsureIndexes exist for the MongoDB collection. EnsureIndexes uses the Background() context, in order
// to pass back the MongoDB errors, rather than any context errors.
func (msc *MongoStoreClient) EnsureIndexes(ctx context.Context) error {
	usersIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "userid", Value: 1}},
			Options: options.Index().
				SetCollation(usersCollation).
				SetUnique(true).
				SetBackground(true),
		},
		{
			Keys: bson.D{{Key: "username", Value: 1}},
			Options: options.Index().
				SetCollation(usersCollation).
				SetBackground(true),
		},
		{
			Keys: bson.D{{Key: "emails", Value: 1}},
			Options: options.Index().
				SetCollation(usersCollation).
				SetBackground(true),
		},
	}

	if _, err := usersCollection(msc).Indexes().CreateMany(ctx, usersIndexes); err != nil {
		log.Fatal(userStoreAPIPrefix, fmt.Sprintf("Unable to create users indexes: %s", err))
	}

	// Add indexes for tokens
	tokenIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "expiresAt", Value: 1}},
			Options: options.Index().
				SetName("ExpireTokens").
				SetExpireAfterSeconds(0).
				SetBackground(true),
		},
		{
			Keys: bson.D{{Key: "userId", Value: 1}},
			Options: options.Index().
				SetName("TokenUserId").
				SetBackground(true),
		},
	}

	if _, err := tokensCollection(msc).Indexes().CreateMany(ctx, tokenIndexes); err != nil {
		log.Fatal(userStoreAPIPrefix, fmt.Sprintf("Unable to create token indexes: %s", err))
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
func (msc *MongoStoreClient) Ping(ctx context.Context) error {
	// do we have a store session
	return msc.client.Ping(ctx, nil)
}

// Disconnect from the MongoDB database
func (msc *MongoStoreClient) Disconnect(ctx context.Context) error {
	return msc.client.Disconnect(ctx)
}

// UpsertUser - Update an existing user's details, or insert a new user if the user doesn't already exist.
func (msc *MongoStoreClient) UpsertUser(ctx context.Context, user *User) error {
	if user.Roles != nil {
		sort.Strings(user.Roles)
	}

	// if the user already exists we update otherwise we add
	opts := options.FindOneAndUpdate().SetUpsert(true).SetCollation(usersCollation)
	result := usersCollection(msc).FindOneAndUpdate(ctx, bson.M{"userid": user.Id}, bson.D{{Key: "$set", Value: user}}, opts)
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// FindUser - find and return an existing user
func (msc *MongoStoreClient) FindUser(ctx context.Context, user *User) (result *User, err error) {
	if user.Id != "" {
		opts := options.FindOne().SetCollation(usersCollation)
		if err = usersCollection(msc).FindOne(ctx, bson.M{"userid": user.Id}, opts).Decode(&result); err != nil {
			return result, err
		}
	}

	return result, nil
}

// FindUsers - find and return multiple existing users
func (msc *MongoStoreClient) FindUsers(ctx context.Context, user *User) (results []*User, err error) {
	fieldsToMatch := []bson.M{}

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"userid": user.Id})
	}
	if user.Username != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"username": user.Username})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": bson.M{"$in": user.Emails}})
	}

	if len(fieldsToMatch) == 0 {
		return []*User{}, nil
	}

	opts := options.Find().SetCollation(usersCollation)
	cursor, err := usersCollection(msc).Find(ctx, bson.M{"$or": fieldsToMatch}, opts)
	if err != nil {
		return nil, err
	}

	if err = cursor.All(ctx, &results); err != nil {
		return results, err
	}

	if results == nil {
		log.Printf("no users found: query: (Id = %v) OR (Name ~= %v) OR (Emails IN %v)", user.Id, user.Username, user.Emails)
		results = []*User{}
	}

	return results, nil
}

// FindUsersByRole - find and return multiple users matching a Role
func (msc *MongoStoreClient) FindUsersByRole(ctx context.Context, role string) (results []*User, err error) {
	opts := options.Find().SetCollation(usersCollation)
	cursor, err := usersCollection(msc).Find(ctx, bson.M{"roles": role}, opts)
	if err != nil {
		return nil, err
	}

	if err = cursor.All(ctx, &results); err != nil {
		return results, err
	}

	if results == nil {
		log.Printf("no users found: query: role: %v", role)
		results = []*User{}
	}

	return results, nil
}

// FindUsersWithIds - find and return multiple users by Tidepool User ID
func (msc *MongoStoreClient) FindUsersWithIds(ctx context.Context, ids []string) (results []*User, err error) {
	opts := options.Find().SetCollation(usersCollation)
	cursor, err := usersCollection(msc).Find(ctx, bson.M{"userid": bson.M{"$in": ids}}, opts)
	if err != nil {
		return nil, err
	}

	if err = cursor.All(ctx, &results); err != nil {
		return results, err
	}

	if results == nil {
		log.Printf("no users found: query: id: %v", ids)
		results = []*User{}
	}

	return results, nil
}

// RemoveUser - Remove a user from the database
func (msc *MongoStoreClient) RemoveUser(ctx context.Context, user *User) (err error) {
	opts := options.FindOneAndDelete().SetCollation(usersCollation)
	result := usersCollection(msc).FindOneAndDelete(ctx, bson.M{"userid": user.Id}, opts)
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// AddToken to the token collection
func (msc *MongoStoreClient) AddToken(ctx context.Context, st *SessionToken) error {
	// if the token already exists we update otherwise we add
	opts := options.FindOneAndUpdate().SetUpsert(true)
	result := tokensCollection(msc).FindOneAndUpdate(ctx, bson.M{"_id": st.ID}, bson.D{{Key: "$set", Value: st}}, opts)
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}

	return nil
}

// FindTokenByID - find an auth token by its ID
func (msc *MongoStoreClient) FindTokenByID(ctx context.Context, id string) (*SessionToken, error) {
	sessionToken := &SessionToken{}
	if err := tokensCollection(msc).FindOne(ctx, bson.M{"_id": id}).Decode(&sessionToken); err != nil {
		return nil, err
	}

	return sessionToken, nil
}

// RemoveTokenByID - delete an auth token matching an ID
func (msc *MongoStoreClient) RemoveTokenByID(ctx context.Context, id string) (err error) {
	result := tokensCollection(msc).FindOneAndDelete(ctx, bson.M{"_id": id})
	if result.Err() != mongo.ErrNoDocuments {
		return result.Err()
	}
	return nil
}

// RemoveTokensForUser - delete an auth token matching an ID
func (msc *MongoStoreClient) RemoveTokensForUser(ctx context.Context, userId string) (err error) {
	_, err = tokensCollection(msc).DeleteMany(ctx, bson.M{"userId": userId})
	return
}
