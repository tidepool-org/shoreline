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

	type Config struct {
		Mongo *mongo.Config `json:"mongo"`
	}

	var config Config

	if jsonConfig, err := ioutil.ReadFile("../config/server.json"); err == nil {

		if err := json.Unmarshal(jsonConfig, &config); err != nil {
			log.Fatal(err)
		}

		log.Println("config is", config.Mongo)

		mc := NewMongoStoreClient(config.Mongo)

		/*
		 * INIT THE TEST - we use a clean copy of the collection before we start
		 */

		if err := mc.usersC.DropCollection(); err != nil {
			t.Fatalf("We couldn't drop the users collection and start the tests fresh ", err)
		}

		if err := mc.usersC.Create(&mgo.CollectionInfo{}); err != nil {
			t.Fatalf("We couldn't created the users collection for these tests ", err)
		}

		/*
		 * THE TESTS
		 */
		user, _ := api.NewUser("test user", "myT35t", []string{""})

		if err := mc.UpsertUser(user); err != nil {
			t.Fatalf("we could not create the user %v", err)
		}

		user.Name = "test user updated"

		if err := mc.UpsertUser(user); err != nil {
			t.Fatalf("we could not update the user %v", err)
		}

		toFind := &api.User{Name: user.Name}

		if found, err := mc.GetUser(toFind); err != nil {
			t.Fatalf("we could find the the user %v", toFind)
		} else {
			if found.Name != toFind.Name {
				t.Fatalf("the user we found doesn't match what we asked for %v", found)
			}
		}

	} else {
		t.Fatalf("wtf - failed parsing the config %v", err)
	}
}
