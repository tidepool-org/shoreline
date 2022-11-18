package user

import (
	"context"
	"fmt"
	"regexp"

	log "github.com/sirupsen/logrus"

	goComMgo "github.com/mdblp/go-db/mongo"
	"github.com/mdblp/shoreline/common/logging"
	"github.com/mdblp/shoreline/token"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	USERS_COLLECTION  = "users"
	TOKENS_COLLECTION = "tokens"
	DIRTY_COLLECTION  = "dirty"
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

func mgoDirtyCollection(c *Client) *mongo.Collection {
	return c.Collection(DIRTY_COLLECTION)
}

func (c *Client) UpsertUser(ctx context.Context, user *User) error {
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

func (c *Client) findDirtyUser(ctx context.Context, filter interface{}, resultMessage string) (found bool) {
	var results []*User
	log := logging.FromContext(ctx)
	cursor, err := mgoDirtyCollection(c).Find(ctx, filter)
	if err != nil {
		return false
	}
	defer cursor.Close(ctx)
	if err = cursor.All(ctx, &results); err != nil {
		log.Info(resultMessage)
		return true
	}
	if results == nil {
		log.Infof("no %v", resultMessage)
		return false
	}
	return true
}

func (c *Client) UpsertDirty(ctx context.Context, username string) error {
	options := options.Update().SetUpsert(true)
	update := bson.M{"$set": bson.M{"username": username}}
	// if the user already exists we update otherwise we add
	_, err := mgoDirtyCollection(c).UpdateOne(ctx, bson.M{"username": username}, update, options)
	return err
}

func (c *Client) findUsers(ctx context.Context, filter interface{}, noResultMessage string) (results []*User, err error) {
	log := logging.FromContext(ctx)
	cursor, err := mgoUsersCollection(c).Find(ctx, filter)
	if err != nil {
		return results, err
	}
	defer cursor.Close(ctx)
	err = cursor.All(ctx, &results)
	if err != nil {
		return results, err
	}
	if results == nil {
		log.Info(noResultMessage)
		results = []*User{}
	}

	return results, nil
}

func (c *Client) ExistDirtyUser(ctx context.Context, username string) (res bool) {

	fieldsToMatch := []bson.M{}

	if username != "" {
		regexFilter := primitive.Regex{Pattern: fmt.Sprintf(`^%s$`, regexp.QuoteMeta(username)), Options: "i"}
		fieldsToMatch = append(fieldsToMatch, bson.M{"username": bson.M{"$regex": regexFilter}})
	}

	if len(fieldsToMatch) == 0 {
		return false
	}
	userMessage := fmt.Sprintf("user found: query: (Name ~= %v)", username)
	return c.findDirtyUser(ctx, bson.M{"$or": fieldsToMatch}, userMessage)
}

func (c *Client) FindUsers(ctx context.Context, user *User) (results []*User, err error) {

	fieldsToMatch := []bson.M{}

	if user.Id != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"userid": user.Id})
	}
	if user.FrProId != "" {
		fieldsToMatch = append(fieldsToMatch, bson.M{"frProId": user.FrProId})
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

func (c *Client) FindUsersByEmailVerified(ctx context.Context, emailVerified bool) ([]*User, error) {
	noUserMessage := fmt.Sprintf("no users found: query: emailVerified: %v", emailVerified)
	return c.findUsers(ctx, bson.M{"authenticated": emailVerified}, noUserMessage)
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
