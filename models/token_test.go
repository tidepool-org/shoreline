package models

import (
	"net/http"
	"testing"
	"time"
)

type tokenTestData struct {
	data       *Data
	secretUsed string
}

func TestGetSessionToken(t *testing.T) {

	tokenKey := "x-tidepool-session-token"
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Add(tokenKey, "123-456-test-token")

	token := GetSessionToken(request.Header)

	if token.Token != request.Header.Get(tokenKey) {
		t.Fatalf("session value should have been set for token")
	}
}

func TestGenerateSessionTokenWhenNoUserId(t *testing.T) {

	testData := tokenTestData{data: &Data{UserId: "", IsServer: false, Duration: 3600}, secretUsed: "my secret"}

	if _, err := NewSessionToken(testData.data, testData.secretUsed); err == nil {
		t.Fatalf("should not generate a session token if there is no userid")
	}
}

func TestGenerateSessionToken(t *testing.T) {

	testData := tokenTestData{data: &Data{UserId: "12-99-100", IsServer: false, Duration: 3600}, secretUsed: "my secret"}

	if token, _ := NewSessionToken(testData.data, testData.secretUsed); token.Token == "" || token.Time == "" {
		t.Fatalf("should generate a session token")
	}

}

func TestGenerateSessionTokenForServer(t *testing.T) {

	testData := tokenTestData{data: &Data{UserId: "shoreline", IsServer: true, Duration: 3600}, secretUsed: "my secret"}

	if token, _ := NewSessionToken(testData.data, testData.secretUsed); token.Token == "" || token.Time == "" {
		t.Fatalf("should generate a session token")
	}

}

func TestUnpackedData(t *testing.T) {

	testData := tokenTestData{data: &Data{UserId: "111", IsServer: true, Duration: 3600}, secretUsed: "my other secret"}

	token, _ := NewSessionToken(testData.data, testData.secretUsed)

	if ok := token.Verify(testData.secretUsed); ok == false {
		t.Fatalf("unpacked token should be valid")
	}

	if token.data.IsServer == false {
		t.Fatalf(" token should have been what was given")
	}

	if token.data.Duration != testData.data.Duration {
		t.Fatalf("the duration should have been what was given")
	}

	if token.data.UserId != testData.data.UserId {
		t.Fatalf("the user should have been what was given")
	}

}

func TestUnpackTokenExpires(t *testing.T) {

	testData := tokenTestData{data: &Data{UserId: "2341", IsServer: false, Duration: 1}, secretUsed: "my secret"}

	token, _ := NewSessionToken(testData.data, testData.secretUsed)

	time.Sleep(2 * time.Second) //ensure token expires

	if ok := token.Verify(testData.secretUsed); ok != false {
		t.Fatalf("the token should have expired")
	}

}

func TestVerifyStoredToken(t *testing.T) {

	testData := tokenTestData{data: &Data{UserId: "2341", IsServer: false, Duration: 1200}, secretUsed: "my secret"}

	token, _ := NewSessionToken(testData.data, testData.secretUsed)

	if ok := token.Verify(testData.secretUsed); ok == false {
		t.Fatalf("the token should not have expired")
	}
}
