package clients

import (
	"./../models"
	"encoding/json"
	"github.com/tidepool-org/go-common/clients/mongo"
	"io/ioutil"
	"labix.org/v2/mgo"
	"strings"
	"testing"
)

func TestMongoStoreUserOperations(t *testing.T) {

	type (
		Config struct {
			Mongo *mongo.Config `json:"mongo"`
		}
	)

	var (
		config           Config
		ORIG_USR_DETAIL  = &models.UserDetail{Name: "Test User", Emails: []string{"test@foo.bar"}, Pw: "myT35t"}
		OTHER_USR_DETAIL = &models.UserDetail{Name: "Second User", Emails: ORIG_USR_DETAIL.Emails, Pw: "my0th3rT35t"}
	)

	const FAKE_SALT = "some fake salt for the tests"

	testingConfig := &mongo.Config{ConnectionString: "mongodb://localhost/user_test"}

	mc := NewMongoStoreClient(testingConfig)

	/*
	 * INIT THE TEST - we use a clean copy of the collection before we start
	 */

	//just drop and don't worry about any errors
	mc.session.DB("").C(USERS_COLLECTION).DropCollection()

	if err := mc.session.DB("").C(USERS_COLLECTION).Create(&mgo.CollectionInfo{}); err != nil {
		t.Fatalf("We couldn't created the users collection for these tests ", err)
	}

	/*
	 * THE TESTS
	 */
	user, _ := models.NewUser(ORIG_USR_DETAIL, FAKE_SALT)

	if err := mc.UpsertUser(user); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	/*
	 * Find by Name
	 */

	toFindByOriginalName := &models.User{Name: user.Name}

	if found, err := mc.FindUsers(toFindByOriginalName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) > 0 && found[0].Name != toFindByOriginalName.Name && found[0].Name != ORIG_USR_DETAIL.Name {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}
	//UPPER CASE
	byUpperName := &models.User{Name: strings.ToUpper(user.Name)}

	if found, err := mc.FindUsers(byUpperName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) == 0 {
			t.Fatalf("No users were found for ", byUpperName.Name)
		} else if strings.ToUpper(found[0].Name) != byUpperName.Name {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}
	//lower case
	byLowerName := &models.User{Name: strings.ToLower(user.Name)}

	if found, err := mc.FindUsers(byLowerName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) == 0 {
			t.Fatalf("No users were found for ", byLowerName.Name)
		} else if strings.ToLower(found[0].Name) != byLowerName.Name {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	//Do an update
	user.Name = "test user updated"

	if err := mc.UpsertUser(user); err != nil {
		t.Fatalf("we could not update the user %v", err)
	}

	//By Name
	toFindByName := &models.User{Name: user.Name}

	if found, err := mc.FindUsers(toFindByName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) != 1 {
			t.Logf("results: %v ", found)
			t.Fatalf("there should only be 1 match be we found %v", len(found))
		}
		if found[0].Name != toFindByName.Name {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	/*
	 * Find by Email
	 */

	//By Email
	byEmails := &models.User{Emails: user.Emails}

	if found, err := mc.FindUsers(byEmails); err != nil {
		t.Fatalf("we could not find the the user by emails %v", byEmails)
	} else {
		if len(found) != 1 {
			t.Logf("results: %v ", found)
			t.Fatalf("there should only be 1 match be we found %v", len(found))
		}
		if found[0].Emails[0] != byEmails.Emails[0] {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	//By Id
	toFindById := &models.User{Id: user.Id}

	if found, err := mc.FindUser(toFindById); err != nil {
		t.Fatalf("we could not find the the user by id err[%v]", err)
	} else {
		if found.Id != toFindById.Id {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	//Find many By Email - user and userTwo have the same emails addresses
	userTwo, _ := models.NewUser(OTHER_USR_DETAIL, FAKE_SALT)

	if err := mc.UpsertUser(userTwo); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	toMultipleByEmails := &models.User{Emails: user.Emails}

	if found, err := mc.FindUsers(toMultipleByEmails); err != nil {
		t.Fatalf("we could not find the the users by emails %v", toMultipleByEmails)
	} else if len(found) != 2 {
		t.Logf("results: %v ", found)
		t.Fatalf("there should be 2 match's be we found %v", len(found))
	}

}

func TestMongoStoreTokenOperations(t *testing.T) {

	type Config struct {
		Mongo *mongo.Config `json:"mongo"`
	}

	var (
		config Config
		TD     = &models.TokenData{UserId: "2341", IsServer: true, DurationSecs: 3600}
	)

	const (
		FAKE_SECRET = "some secret for the tests"
	)

	testingConfig := &mongo.Config{ConnectionString: "mongodb://localhost/user_test"}

	mc := NewMongoStoreClient(testingConfig)

	/*
	 * INIT THE TEST - we use a clean copy of the collection before we start
	 */

	//drop and don't worry about any errors
	//just drop and don't worry about any errors
	mc.session.DB("").C(TOKENS_COLLECTION).DropCollection()

	if err := mc.session.DB("").C(TOKENS_COLLECTION).Create(&mgo.CollectionInfo{}); err != nil {
		t.Fatalf("We couldn't created the token collection for these tests ", err)
	}

	/*
	 * THE TESTS
	 */
	sessionToken, _ := models.NewSessionToken(TD, FAKE_SECRET)

	if err := mc.AddToken(sessionToken); err != nil {
		t.Fatalf("we could not save the token %v", err)
	}

	if foundToken, err := mc.FindToken(sessionToken); err == nil {
		if foundToken.Id == "" {
			t.Fatalf("the token string isn't included %v", foundToken)
		}
		if foundToken.Time == 0 {
			t.Fatalf("the time wasn't included %v", foundToken)
		}
	} else {
		t.Fatalf("no token was returned when it should have been - err[%v]", err)
	}

	if err := mc.RemoveToken(sessionToken); err != nil {
		t.Fatalf("we could not remove the token %v", err)
	}

	if token, err := mc.FindToken(sessionToken); err == nil {
		if token != nil {
			t.Fatalf("the token has been removed so we shouldn't find it %v", token)
		}
	}

}
