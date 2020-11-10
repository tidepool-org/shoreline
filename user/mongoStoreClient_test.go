package user

import (
	"context"
	"strings"
	"testing"
	"time"

	tpMongo "github.com/tidepool-org/go-common/clients/mongo"
)

var testingConfig = &tpMongo.Config{ConnectionString: "mongodb://127.0.0.1/user_test", Database: "user_test"}

func mongoTestSetup() (*MongoStoreClient, error) {
	mc := NewMongoStoreClient(testingConfig)

	/*
	 * INIT THE TEST - we use a clean copy of the collection before we start
	 */
	//just drop and don't worry about any errors
	usersCollection(mc).Drop(context.Background())

	return mc, nil
}

func TestMongoStoreUserOperations(t *testing.T) {

	var (
		usernameOriginal   = "test@foo.bar"
		usernameOther      = "other@foo.bar"
		password           = "myT35ter"
		originalUserDetail = &NewUserDetails{Username: &usernameOriginal, Emails: []string{usernameOriginal}, Password: &password}
		otherUserDetail    = &NewUserDetails{Username: &usernameOther, Emails: originalUserDetail.Emails, Password: &password}
	)

	const testsFakeSalt = "some fake salt for the tests"

	mc, err := mongoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	user, err := NewUser(originalUserDetail, testsFakeSalt)
	if err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if err := mc.UpsertUser(context.Background(), user); err != nil {
		t.Fatalf("we could not upsert the user %v", err)
	}

	/*
	 * Find by Username
	 */

	toFindByOriginalName := &User{Username: user.Username}

	if found, err := mc.FindUsers(context.Background(), toFindByOriginalName); err != nil {
		t.Fatalf("we could not find the the user by name: err[%v]", err)
	} else {
		if len(found) > 0 && found[0].Username != toFindByOriginalName.Username && found[0].Username != *originalUserDetail.Username {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}
	//UPPER CASE
	byUpperName := &User{Username: strings.ToUpper(user.Username)}

	if found, err := mc.FindUsers(context.Background(), byUpperName); err != nil {
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

	if found, err := mc.FindUsers(context.Background(), byLowerName); err != nil {
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

	if err := mc.UpsertUser(context.Background(), user); err != nil {
		t.Fatalf("we could not update the user %v", err)
	}

	//By Username
	toFindByName := &User{Username: user.Username}

	if found, err := mc.FindUsers(context.Background(), toFindByName); err != nil {
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

	if found, err := mc.FindUsers(context.Background(), byEmails); err != nil {
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
	toFindByID := &User{Id: user.Id}

	if found, err := mc.FindUser(context.Background(), toFindByID); err != nil {
		t.Fatalf("we could not find the the user by id err[%v]", err)
	} else {
		if found.Id != toFindByID.Id {
			t.Fatalf("the user we found doesn't match what we asked for %v", found)
		}
	}

	//Find many By Email - user and userTwo have the same emails addresses
	userTwo, err := NewUser(otherUserDetail, testsFakeSalt)
	if err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if err := mc.UpsertUser(context.Background(), userTwo); err != nil {
		t.Fatalf("we could not upsert the user %v", err)
	}

	toMultipleByEmails := &User{Emails: user.Emails}

	if found, err := mc.FindUsers(context.Background(), toMultipleByEmails); err != nil {
		t.Fatalf("we could not find the the users by emails %v", toMultipleByEmails)
	} else if len(found) != 2 {
		t.Logf("results: %v ", found)
		t.Fatalf("there should be 2 match's be we found %v", len(found))
	}

}

func TestMongoStore_FindUsersByRole(t *testing.T) {

	var (
		testsFakeSalt = "some fake salt for the tests"
		userOneName   = "test@foo.bar"
		userTwoName   = "test_two@foo.bar"
		userPw        = "my0th3rT35t"
		userOneDetail = &NewUserDetails{Username: &userOneName, Emails: []string{userOneName}, Password: &userPw}
		userTwoDetail = &NewUserDetails{Username: &userTwoName, Emails: []string{userTwoName}, Password: &userPw}
	)

	mc, err := mongoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	userOne, _ := NewUser(userOneDetail, testsFakeSalt)
	userOne.Roles = append(userOne.Roles, "clinic")

	userTwo, _ := NewUser(userTwoDetail, testsFakeSalt)

	if err := mc.UpsertUser(context.Background(), userOne); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}
	if err := mc.UpsertUser(context.Background(), userTwo); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if found, err := mc.FindUsersByRole(context.Background(), "clinic"); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 1 || found[0].Roles[0] != "clinic" {
		t.Fatalf("should only find clinic users but found %v", found)
	}

}

func TestMongoStore_FindUsersById(t *testing.T) {

	var (
		testsFakeSalt = "some fake salt for the tests"
		userOneName   = "test@foo.bar"
		userTwoName   = "test_two@foo.bar"
		userPw        = "my0th3rT35t"
		userOneDetail = &NewUserDetails{Username: &userOneName, Emails: []string{userOneName}, Password: &userPw}
		userTwoDetail = &NewUserDetails{Username: &userTwoName, Emails: []string{userTwoName}, Password: &userPw}
	)

	mc, err := mongoTestSetup()
	if err != nil {
		t.Fatalf("we could not initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	userOne, _ := NewUser(userOneDetail, testsFakeSalt)
	userTwo, _ := NewUser(userTwoDetail, testsFakeSalt)

	if err := mc.UpsertUser(context.Background(), userOne); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}
	if err := mc.UpsertUser(context.Background(), userTwo); err != nil {
		t.Fatalf("we could not create the user %v", err)
	}

	if found, err := mc.FindUsersWithIds(context.Background(), []string{userOne.Id}); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 1 || found[0].Id != userOne.Id {
		t.Fatalf("should only find user ID %s but found %v", userOne.Id, found)
	}

	if found, err := mc.FindUsersWithIds(context.Background(), []string{userTwo.Id}); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 1 || found[0].Id != userTwo.Id {
		t.Fatalf("should only find user ID %s but found %v", userTwo.Id, found)
	}

	if found, err := mc.FindUsersWithIds(context.Background(), []string{userOne.Id, userTwo.Id}); err != nil {
		t.Fatalf("error finding users by role %s", err.Error())
	} else if len(found) != 2 || found[0].Id != userOne.Id || found[1].Id != userTwo.Id {
		t.Fatalf("should only find user ID %s but found %v", userTwo.Id, found)
	}
}

func TestMongoStoreTokenOperations(t *testing.T) {

	testingTokenData := &TokenData{UserId: "2341", IsServer: true, DurationSecs: 3600}
	testingTokenConfig := TokenConfig{
		DurationSecs: 1200,
		EncodeKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzg3MHpXfMuH4AJ4URtaG4QvZenpfuSz2FmIwdnPEtkrKFmL2
6b89U1tw5WsYAE158znAzPptDA25hAsIcTAqULNsoY3WV2zmsLrUX8pUaCTfExXN
dMFDruR676G3pJWcsI1GuePK5/v3dBHjjTYdtVJiogbCtP+XYT/k1qHZztwRY4oH
Ma8LorxUZco0Mf6qOq5tmRUJhxvCESaqUTpTAIIfByMnPmnIHOHnsYtkiZQBms2x
o1UfpYnqZX2CoN+wPoMoSAlRbnOmmHYbbMFVPNTj7NINwVb8K8iDU7lFR+JfN3UG
lErVo7XCDQcbwTpiZbdj9zWSWbYtIBNBqkNxxwIDAQABAoIBAG3IMhmVlh6BAGYr
0vfO8nvSmWNE8d0yFEbmt5VUptjMzhDRV2ZAascPr/27akU3AiNRgOR1BEZoxY+R
ZUUQ+WqXvefxLuLTdbFxSRdkMEZwZp2/fwCWu53hw5IK4lIBGEOEccs2j3O77iJc
KZWh4IArzbsvyOswRhIdPaoQ/3/TECPa5AXY7LAEj32XfP3K08rRAldgdfTv6XbV
e/pzKMzqgPMIhZ3mG1n7CJ+DLhajEEG36KwszI6OttkjzyBzlsQb3rskEOypG3ZU
k24B++v3Cm7FN0vG+FLFVzwS5rDrF+CUIFCyQU/nAB8nmkiNdCbDI0/614NeSSnE
BZc6G1ECgYEA/zVJdpRx5kgFDyxmJrdVcXJ/digGDct6og0pffcJW1ygBnt+tLRd
gpH+oBNUMz92GKb+wTTlOba0CNbJULM1sZklf604yzpIDji0HyI2oZ0fo+OEkpBz
PyNrdnm2WXF4e3WCb1ehkxGMyfTH70RFKqmPRMka1xWAMXPgbP5Osj8CgYEAzrF3
iAX+geyqagzQfbt5bf9zePmL4Dx6J37pgtZSo88sqtSU6+eYQsF/pS5KrtxD6Sql
5qSbfKekmDhEF4DMUeva76JHmPIPdJH+fPyw6jOB6S3tS+i41S2CGNub1RLz7LCj
NEZ9H5GBVmxBTdiZL3aZWgIxo63Nl0H39k6+TnkCgYEA44Nkx5LU659+6yUAuDku
seGKIhLSOtAQtpEXUVW/ALTVcJH9xikZSALRRXGV2c4UgSu25xU52Ta4zzxz4j6x
em92D5mkjQCbJhqE8VB19aP2hguZr3OZWktATTF6T8ipyR5cNtifkVXO9mgDKZnq
M3tP3tmN1Ps0+mE8TM51588CgYBZYgtz6kuued8UL2h2Bv2zINYZyajAlsaoj8yB
hReFuVDyqy2feq6wp6cAkq0/QwenLIdD34lR9dlK7oIbu9ofzyQFnyLhNESUv5HT
ER+cmBuk7/R/cCuGHMD26PlRwnlzsMtTDuyLG0xYSEZRWMqd6ObWMr6urrmKoL+P
Z2wK2QKBgQC7SZ47YM45pz23yjyrKx6dUAfw5imb6ylZPft24A+W2tFanfRDQITX
wGHgJHaV+gd52zrP6s8AKzMjMcRtB0g0CGf5Qe1BHMh89fJsUKToT8L+040kWl/P
upYmRYNT7J2Met0WVB6u6ZDFSMl+CIFLXHGtU47DjGUmQxqmhW8LOg==
-----END RSA PRIVATE KEY-----`,
		DecodeKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzg3MHpXfMuH4AJ4URtaG
4QvZenpfuSz2FmIwdnPEtkrKFmL26b89U1tw5WsYAE158znAzPptDA25hAsIcTAq
ULNsoY3WV2zmsLrUX8pUaCTfExXNdMFDruR676G3pJWcsI1GuePK5/v3dBHjjTYd
tVJiogbCtP+XYT/k1qHZztwRY4oHMa8LorxUZco0Mf6qOq5tmRUJhxvCESaqUTpT
AIIfByMnPmnIHOHnsYtkiZQBms2xo1UfpYnqZX2CoN+wPoMoSAlRbnOmmHYbbMFV
PNTj7NINwVb8K8iDU7lFR+JfN3UGlErVo7XCDQcbwTpiZbdj9zWSWbYtIBNBqkNx
xwIDAQAB
-----END PUBLIC KEY-----`,
		Algorithm: "RS256",
		Audience:  "localhost",
		Issuer:    "localhost",
	}

	mc, err := mongoTestSetup()
	if err != nil {
		t.Fatalf("we initialise the test store %s", err.Error())
	}

	/*
	 * THE TESTS
	 */
	sessionToken, _ := CreateSessionToken(
		testingTokenData,
		testingTokenConfig,
	)

	if err := mc.AddToken(context.Background(), sessionToken); err != nil {
		t.Fatalf("we could not save the token %v", err)
	}

	if foundToken, err := mc.FindTokenByID(context.Background(), sessionToken.ID); err == nil {
		if foundToken.ID == "" {
			t.Fatalf("the token string isn't included %v", foundToken)
		}
		if foundToken.Time == time.Unix(0, 0) {
			t.Fatalf("the time wasn't included %v", foundToken)
		}
	} else {
		t.Fatalf("no token was returned when it should have been - err[%v]", err)
	}

	if err := mc.RemoveTokenByID(context.Background(), sessionToken.ID); err != nil {
		t.Fatalf("we could not remove the token %v", err)
	}

	if token, err := mc.FindTokenByID(context.Background(), sessionToken.ID); err == nil {
		if token != nil {
			t.Fatalf("the token has been removed so we shouldn't find it %v", token)
		}
	}

}
