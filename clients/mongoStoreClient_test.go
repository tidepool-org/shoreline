package clients

import (
	"encoding/json"
	mongo "github.com/tidepool-org/go-common/clients/mongo"
	api "github.com/tidepool-org/shoreline/api"
	"io/ioutil"
	"labix.org/v2/mgo"
	"log"
	"testing"
)

func TestMongoStoreUserOperations(t *testing.T) {

	var config *mongo.Config

	if jsonConfig, err := ioutil.ReadFile("./config/server.json"); err == nil {

		if err := json.Unmarshal(jsonConfig, &config); err != nil {
			log.Fatal(err)
		}

		mc := NewStoreClient(config)

		/*
		 * INIT THE TEST - we use a clean copy of the collection before we start
		 */
		if err := mc.usersC.DropCollection(); err != nil {
			t.Fatalf("We couldn't drop the users collection and start the tests fresh")
		}

		if err := mc.usersC.Create(&mgo.CollectionInfo{}); err != nil {
			t.Fatalf("We couldn't created the users collection for these tests")
		}

		/*
		 * THE TESTS
		 */
		user, _ := api.NewUser("test user", "myT35t", []string{""})

		if err := mc.UpsertUser(user); err != nil {
			t.Fatalf("we could not create the user %v", user)
		}
	}
}
