package models

import (
	"testing"
	"time"
)

type tokenTestData struct {
	data       *TokenData
	secretUsed string
}

func TestGetSessionToken(t *testing.T) {

	tokenString := "123-456-test-token"

	token := GetSessionToken(tokenString)

	if token.Token != tokenString {
		t.Fatalf("session value should have been set for token")
	}
}

func TestGenerateSessionTokenWhenNoUserId(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "", IsServer: false, DurationSecs: 3600}, secretUsed: "my secret"}

	if _, err := NewSessionToken(testData.data, testData.secretUsed); err == nil {
		t.Fatalf("should not generate a session token if there is no userid")
	}
}

func TestGenerateSessionToken(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "12-99-100", IsServer: false, DurationSecs: 3600}, secretUsed: "my secret"}

	if token, _ := NewSessionToken(testData.data, testData.secretUsed); token.Token == "" || token.Time == "" {
		t.Fatalf("should generate a session token")
	}

}

func TestGenerateSessionTokenForServer(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "shoreline", IsServer: true, DurationSecs: 3600}, secretUsed: "my secret"}

	if token, _ := NewSessionToken(testData.data, testData.secretUsed); token.Token == "" || token.Time == "" {
		t.Fatalf("should generate a session token")
	}

}

func TestUnpackedData(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "111", IsServer: true, DurationSecs: 3600}, secretUsed: "my other secret"}

	token, _ := NewSessionToken(testData.data, testData.secretUsed)

	if ok := token.UnpackAndVerify(testData.secretUsed); ok == false {
		t.Fatalf("unpacked token should be valid")
	}

	if token.TokenData.IsServer == false {
		t.Fatalf(" token should have been what was given")
	}

	if token.TokenData.DurationSecs != testData.data.DurationSecs {
		t.Fatalf("the DurationSecs should have been what was given")
	}

	if token.TokenData.UserId != testData.data.UserId {
		t.Fatalf("the user should have been what was given")
	}

}

func TestUnpackTokenExpires(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1}, secretUsed: "my secret"}

	token, _ := NewSessionToken(testData.data, testData.secretUsed)

	time.Sleep(2 * time.Second) //ensure token expires

	if ok := token.UnpackAndVerify(testData.secretUsed); ok != false {
		t.Fatalf("the token should have expired")
	}

}

func TestUnpackAndVerifyStoredToken(t *testing.T) {

	testData := tokenTestData{data: &TokenData{UserId: "2341", IsServer: false, DurationSecs: 1200}, secretUsed: "my secret"}

	token, _ := NewSessionToken(testData.data, testData.secretUsed)

	if ok := token.UnpackAndVerify(testData.secretUsed); ok == false {
		t.Fatalf("the token should not have expired")
	}
}
