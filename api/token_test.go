package api

import (
	"net/http"
	"testing"
	"time"
)

type tokenTestData struct {
	userid     string
	duration   float64
	secretUsed string
	isServer   bool
}

func TestGetSessionToken(t *testing.T) {

	tokenKey := "x-tidepool-session-token"
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Add(tokenKey, "123-456-test-token")

	token := GetSessionToken(request.Header)

	if token.tokenString != request.Header.Get(tokenKey) {
		t.Fatalf("session value should have been set for token")
	}
}

func TestGenerateSessionTokenWhenNoUserId(t *testing.T) {

	if _, err := NewSessionToken("", "my secret", 3600, false); err == nil {
		t.Fatalf("should not generate a session token if there is no userid")
	}
}

func TestGenerateSessionToken(t *testing.T) {

	if token, _ := NewSessionToken("2341", "my secret", 3600, false); token.Token == "" || token.Time == "" {
		t.Fatalf("should generate a session token")
	}

}

func TestGenerateSessionTokenForServer(t *testing.T) {

	if token, _ := NewSessionToken("2341", "my secret", 3600, true); token.Token == "" || token.Time == "" {
		t.Fatalf("should generate a session token")
	}

}

func TestUnpackToken(t *testing.T) {

	data := tokenTestData{
		userid:     "111",
		duration:   3600,
		secretUsed: "my other secret",
		isServer:   true,
	}

	token, _ := NewSessionToken(data.userid, data.secretUsed, data.duration, data.isServer)

	jwtToken, _ := token.UnpackToken(data.secretUsed)

	if jwtToken.Valid == false {
		t.Fatalf("unpacked token should be valid")
	}

	if jwtToken.Claims["svr"] != "yes" {
		t.Fatalf(" token should have been what was given")
	}

	if jwtToken.Claims["dur"] != data.duration {
		t.Fatalf("the duration should have been what was given")
	}

	if jwtToken.Claims["usr"] != data.userid {
		t.Fatalf("the user should have been what was given")
	}

}

func TestUnpackTokenExpires(t *testing.T) {

	data := tokenTestData{
		userid:     "2341",
		duration:   1,
		secretUsed: "my secret",
		isServer:   false,
	}

	token, _ := NewSessionToken(data.userid, data.secretUsed, data.duration, data.isServer)

	time.Sleep(2 * time.Second) //ensure token expires

	if _, err := token.UnpackToken(data.secretUsed); err == nil {
		t.Fatalf("the token should have expired")
	}

}

func TestVerifyStoredToken(t *testing.T) {

	data := tokenTestData{
		userid:     "2341",
		duration:   1200,
		secretUsed: "my secret",
		isServer:   false,
	}

	token, _ := NewSessionToken(data.userid, data.secretUsed, data.duration, data.isServer)

	isValid, err := token.VerifyStoredToken(data.secretUsed)

	if err != nil {
		t.Fatalf("the token should have expired")
	}
	if isValid == false {
		t.Fatalf("the token should be valid")
	}

}
