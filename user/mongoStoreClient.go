package user

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sort"

	"github.com/mdblp/shoreline/token"
	goComMgo "github.com/tidepool-org/go-common/clients/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	USERS_COLLECTION  = "users"
	TOKENS_COLLECTION = "tokens"
)

// Client struct
type Client struct {
	*goComMgo.StoreClient
}

// NewStore creates a new Client
func NewStore(config *goComMgo.Config, logger *log.Logger) (*Client, error) {
	client := Client{}
	store, err := goComMgo.NewStoreClient(config, logger)
	client.StoreClient = store
	return &client, err
}

func mgoUsersCollection(c *Client) *mongo.Collection {
	return c.Collection(USERS_COLLECTION)
}

func mgoTokensCollection(c *Client) *mongo.Collection {
	return c.Collection(TOKENS_COLLECTION)
}

func (c *Client) UpsertUser(ctx context.Context, user *User) error {
	if user.Roles != nil {
		sort.Strings(user.Roles)
	}
	options := options.Update().SetUpsert(true)
	update := bson.M{"$set": user}
	// if the user already exists we update otherwise we add
	_, err := mgoUsersCollection(c).UpdateOne(ctx, bson.M{"userid": user.Id}, update, options)
	return err
}

func (c *Client) FindUser(ctx context.Context, user *User) (result *User, err error) {

	if user.Id != "" {
		opts := options.FindOne()
		if err = mgoUsersCollection(c).FindOne(ctx, bson.M{"userid": user.Id}, opts).Decode(&result); err != nil {
			return result, err
		}
	}

	return result, nil
}

func (c *Client) findUsers(ctx context.Context, filter interface{}, noResultMessage string) (results []*User, err error) {
	cursor, err := mgoUsersCollection(c).Find(ctx, filter)
	defer cursor.Close(ctx)
	if err != nil {
		return results, err
	}
	err = cursor.All(ctx, &results)
	if err != nil {
		return results, err
	}
	if results == nil {
		log.Print(noResultMessage)
		results = []*User{}
	}

	return results, nil
}

func (c *Client) FindUsers(ctx context.Context, user *User) (results []*User, err error) {

	fieldsToMatch := []bson.M{}

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"userid": user.Id})
	}
	if user.Username != "" {
		regexFilter := primitive.Regex{Pattern: fmt.Sprintf(`^%s$`, regexp.QuoteMeta(user.Username)), Options: "i"}
		fieldsToMatch = append(fieldsToMatch, bson.M{"username": bson.M{"$regex": regexFilter}})
	}
	if len(user.Emails) > 0 {
		fieldsToMatch = append(fieldsToMatch, bson.M{"emails": bson.M{"$in": user.Emails}})
	}

	if len(fieldsToMatch) == 0 {
		return []*User{}, nil
	}
	noUserMessage := fmt.Sprintf("no users found: query: (Id = %v) OR (Name ~= %v) OR (Emails IN %v)", user.Id, user.Username, user.Emails)
	return c.findUsers(ctx, bson.M{"$or": fieldsToMatch}, noUserMessage)
}

func (c *Client) FindUsersByRole(ctx context.Context, role string) (results []*User, err error) {
	noUserMessage := fmt.Sprintf("no users found: query: role: %v", role)
	return c.findUsers(ctx, bson.M{"roles": role}, noUserMessage)
}

func (c *Client) FindUsersWithIds(ctx context.Context, ids []string) (results []*User, err error) {
	noUserMessage := fmt.Sprintf("no users found: query: id: %v", ids)
	return c.findUsers(ctx, bson.M{"userid": bson.M{"$in": ids}}, noUserMessage)
}

func (c *Client) RemoveUser(ctx context.Context, user *User) (err error) {
	if _, err := mgoUsersCollection(c).DeleteOne(ctx, bson.M{"userid": user.Id}); err != nil {
		return err
	}
	return nil
}

func (c *Client) AddToken(ctx context.Context, st *token.SessionToken) error {
	options := options.Update().SetUpsert(true)
	update := bson.M{"$set": st}
	// if the user already exists we update otherwise we add
	_, err := mgoTokensCollection(c).UpdateOne(ctx, bson.M{"_id": st.ID}, update, options)
	return err
}

func (c *Client) FindTokenByID(ctx context.Context, id string) (*token.SessionToken, error) {
	opts := options.FindOne()
	sessionToken := &token.SessionToken{}
	if err := mgoTokensCollection(c).FindOne(ctx, bson.M{"_id": id}, opts).Decode(sessionToken); err != nil {
		return nil, err
	}
	return sessionToken, nil
}

func (c *Client) RemoveTokenByID(ctx context.Context, id string) (err error) {
	if _, err := mgoTokensCollection(c).DeleteOne(ctx, bson.M{"_id": id}); err != nil {
		return err
	}
	return nil
}
