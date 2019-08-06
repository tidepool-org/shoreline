package user

import (
	"strings"
	"testing"

	"github.com/globalsign/mgo"

	"github.com/tidepool-org/go-common/clients/mongo"
)

func mgoTestSetup() (*MongoStoreClient, error) {
	mc := NewMongoStoreClient(&mongo.Config{ConnectionString: "mongodb://127.0.0.1/user_test"})

	/*
	 * INIT THE TEST - we use a clean copy of the collection before we start
	 */
	cpy := mc.session.Copy()
	defer cpy.Close()

	//just drop and don't worry about any errors
	mgoUsersCollection(cpy).DropCollection()

	if err := mgoUsersCollection(cpy).Create(&mgo.CollectionInfo{}); err != nil {
		return nil, err
	}
	return mc, nil
}

func TestMongoStoreUserOperations(t *testing.T) {

	var (
		usernameOriginal     = "test@foo.bar"
		usernameOther        = "other@foo.bar"
		password             = "myT35ter"
		original_user_detail = &NewUserDetails{Username: &usernameOriginal, Emails: []string{usernameOriginal}, Password: &password}
		other_user_detail    = &NewUserDetails{Username: &usernameOther, Emails: original_user_detail.Emails, Password: &password}
	)

	const tests_fake_salt = "some fake salt for the tests"

	mc, err := mgoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	user, err := NewUser(original_user_detail, tests_fake_salt)
	if err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if err := mc.UpsertUser(user); err != nil {
		t.Fatalf("we could not upsert the user %v", err)
	}

	/*
	 * Find by Username
	 */

	toFindByOriginalName := &User{Username: user.Username}

	if found, err := mc.FindUsers(toFindByOriginalName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) > 0 && found[0].Username != toFindByOriginalName.Username && found[0].Username != *original_user_detail.Username {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}
	//UPPER CASE
	byUpperName := &User{Username: strings.ToUpper(user.Username)}

	if found, err := mc.FindUsers(byUpperName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) == 0 {
			t.Fatal("No users were found for ", byUpperName.Username)
		} else if strings.ToUpper(found[0].Username) != byUpperName.Username {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}
	//lower case
	byLowerName := &User{Username: strings.ToLower(user.Username)}

	if found, err := mc.FindUsers(byLowerName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) == 0 {
			t.Fatal("No users were found for ", byLowerName.Username)
		} else if strings.ToLower(found[0].Username) != byLowerName.Username {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	//Do an update
	user.Username = "test user updated"

	if err := mc.UpsertUser(user); err != nil {
		t.Fatalf("we could not update the user %v", err)
	}

	//By Username
	toFindByName := &User{Username: user.Username}

	if found, err := mc.FindUsers(toFindByName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) != 1 {
			t.Logf("results: %v ", found)
			t.Fatalf("there should only be 1 match be we found %v", len(found))
		}
		if found[0].Username != toFindByName.Username {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	/*
	 * Find by Email
	 */

	//By Email
	byEmails := &User{Emails: user.Emails}

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
	toFindById := &User{Id: user.Id}

	if found, err := mc.FindUser(toFindById); err != nil {
		t.Fatalf("we could not find the the user by id err[%v]", err)
	} else {
		if found.Id != toFindById.Id {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	//Find many By Email - user and userTwo have the same emails addresses
	userTwo, err := NewUser(other_user_detail, tests_fake_salt)
	if err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if err := mc.UpsertUser(userTwo); err != nil {
		t.Fatalf("we could not upsert the user %v", err)
	}

	toMultipleByEmails := &User{Emails: user.Emails}

	if found, err := mc.FindUsers(toMultipleByEmails); err != nil {
		t.Fatalf("we could not find the the users by emails %v", toMultipleByEmails)
	} else if len(found) != 2 {
		t.Logf("results: %v ", found)
		t.Fatalf("there should be 2 match's be we found %v", len(found))
	}

}

func TestMongoStore_FindUsersByRole(t *testing.T) {

	var (
		tests_fake_salt = "some fake salt for the tests"
		user_one_name   = "test@foo.bar"
		user_two_name   = "test_two@foo.bar"
		user_pw         = "my0th3rT35t"
		user_one_detail = &NewUserDetails{Username: &user_one_name, Emails: []string{user_one_name}, Password: &user_pw}
		user_two_detail = &NewUserDetails{Username: &user_two_name, Emails: []string{user_two_name}, Password: &user_pw}
	)

	mc, err := mgoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	userOne, _ := NewUser(user_one_detail, tests_fake_salt)
	userOne.Roles = append(userOne.Roles, "clinic")

	userTwo, _ := NewUser(user_two_detail, tests_fake_salt)

	if err := mc.UpsertUser(userOne); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}
	if err := mc.UpsertUser(userTwo); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if found, err := mc.FindUsersByRole("clinic"); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 1 || found[0].Roles[0] != "clinic" {
		t.Fatalf("should only find clinic users but found %v", found)
	}

}

func TestMongoStore_FindUsersById(t *testing.T) {

	var (
		tests_fake_salt = "some fake salt for the tests"
		user_one_name   = "test@foo.bar"
		user_two_name   = "test_two@foo.bar"
		user_pw         = "my0th3rT35t"
		user_one_detail = &NewUserDetails{Username: &user_one_name, Emails: []string{user_one_name}, Password: &user_pw}
		user_two_detail = &NewUserDetails{Username: &user_two_name, Emails: []string{user_two_name}, Password: &user_pw}
	)

	mc, err := mgoTestSetup()
	if err != nil {
		t.Fatalf("we could not initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	userOne, _ := NewUser(user_one_detail, tests_fake_salt)
	userTwo, _ := NewUser(user_two_detail, tests_fake_salt)

	if err := mc.UpsertUser(userOne); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}
	if err := mc.UpsertUser(userTwo); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if found, err := mc.FindUsersWithIds([]string{userOne.Id}); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 1 || found[0].Id != userOne.Id {
		t.Fatalf("should only find user ID %s but found %v", userOne.Id, found)
	}

	if found, err := mc.FindUsersWithIds([]string{userTwo.Id}); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 1 || found[0].Id != userTwo.Id {
		t.Fatalf("should only find user ID %s but found %v", userTwo.Id, found)
	}

	if found, err := mc.FindUsersWithIds([]string{userOne.Id, userTwo.Id}); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 2 || found[0].Id != userOne.Id || found[1].Id != userTwo.Id {
		t.Fatalf("should only find user ID %s but found %v", userTwo.Id, found)
	}
}

func TestMongoStoreTokenOperations(t *testing.T) {

	testing_token_data := &TokenData{UserId: "2341", IsServer: true, DurationSecs: 3600}
	testing_token_config := TokenConfig{DurationSecs: 1200, Secret: "some secret for the tests"}

	mc, err := mgoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	sessionToken, _ := CreateSessionToken(
		testing_token_data,
		testing_token_config,
	)

	if err := mc.AddToken(sessionToken); err != nil {
		t.Fatalf("we could not save the token %v", err)
	}

	if foundToken, err := mc.FindTokenByID(sessionToken.ID); err == nil {
		if foundToken.ID == "" {
			t.Fatalf("the token string isn't included %v", foundToken)
		}
		if foundToken.Time == 0 {
			t.Fatalf("the time wasn't included %v", foundToken)
		}
	} else {
		t.Fatalf("no token was returned when it should have been - err[%v]", err)
	}

	if err := mc.RemoveTokenByID(sessionToken.ID); err != nil {
		t.Fatalf("we could not remove the token %v", err)
	}

	if token, err := mc.FindTokenByID(sessionToken.ID); err == nil {
		if token != nil {
			t.Fatalf("the token has been removed so we shouldn't find it %v", token)
		}
	}

}
