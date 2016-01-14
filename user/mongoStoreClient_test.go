package user

import (
	"strings"
	"testing"

	"github.com/tidepool-org/go-common/clients/mongo"
	"labix.org/v2/mgo"
)

func mgoTestSetup() (*MongoStoreClient, error) {
	mc := NewMongoStoreClient(&mongo.Config{ConnectionString: "mongodb://localhost/user_test"})

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
		original_user_detail = &UserDetail{Name: "Test User", Emails: []string{"test@foo.bar"}, Pw: "myT35t"}
		other_user_detail    = &UserDetail{Name: "Second User", Emails: original_user_detail.Emails, Pw: "my0th3rT35t"}
	)

	const tests_fake_salt = "some fake salt for the tests"

	mc, err := mgoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	user, _ := NewUser(original_user_detail, tests_fake_salt)

	if err := mc.UpsertUser(user); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	/*
	 * Find by Name
	 */

	toFindByOriginalName := &User{Name: user.Name}

	if found, err := mc.FindUsers(toFindByOriginalName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) > 0 && found[0].Name != toFindByOriginalName.Name && found[0].Name != original_user_detail.Name {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}
	//UPPER CASE
	byUpperName := &User{Name: strings.ToUpper(user.Name)}

	if found, err := mc.FindUsers(byUpperName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) == 0 {
			t.Fatal("No users were found for ", byUpperName.Name)
		} else if strings.ToUpper(found[0].Name) != byUpperName.Name {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}
	//lower case
	byLowerName := &User{Name: strings.ToLower(user.Name)}

	if found, err := mc.FindUsers(byLowerName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) == 0 {
			t.Fatal("No users were found for ", byLowerName.Name)
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
	toFindByName := &User{Name: user.Name}

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
	userTwo, _ := NewUser(other_user_detail, tests_fake_salt)

	if err := mc.UpsertUser(userTwo); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	toMultipleByEmails := &User{Emails: user.Emails}

	if found, err := mc.FindUsers(toMultipleByEmails); err != nil {
		t.Fatalf("we could not find the the users by emails %v", toMultipleByEmails)
	} else if len(found) != 2 {
		t.Logf("results: %v ", found)
		t.Fatalf("there should be 2 match's be we found %v", len(found))
	}

}

func TestMongoStore_FindUsers_ByRole(t *testing.T) {

	const (
		tests_fake_salt = "some fake salt for the tests"
		user_one_name   = "test@foo.bar"
		user_two_name   = "test_two@foo.bar"
		user_pw         = "my0th3rT35t"
	)

	var (
		user_one_detail = &UserDetail{Name: user_one_name, Emails: []string{user_one_name}, Pw: user_pw, Roles: []string{CLINIC_ROLE}}
		user_two_detail = &UserDetail{Name: user_two_name, Emails: []string{user_two_name}, Pw: user_pw}
	)

	mc, err := mgoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
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

	clinicalUsers := &User{Roles: []string{CLINIC_ROLE}}

	if found, err := mc.FindUsers(clinicalUsers); err != nil {
		t.Fatalf("error finsding users by role %s", err.Error())
	} else if len(found) != 1 || found[0].Roles[0] != CLINIC_ROLE {
		t.Fatalf("should only find clinic users but found %v", found)
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
