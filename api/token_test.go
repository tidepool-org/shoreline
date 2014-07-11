package api

import (
	"net/http"
	"testing"
)

func TestGetSessionToken(t *testing.T) {

	tokenKey := "x-tidepool-session-token"
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Add(tokenKey, "123-456-test-token")

	token := GetSessionToken(request.Header)

	if token.session != request.Header.Get(tokenKey) {
		t.Fatalf("session value should have been set for token")
	}
}

func TestGenerateSessionTokenWhenNoUserId(t *testing.T) {

	if token := GenerateSessionToken("", "my secret", 3600, false); token.session != "" {
		t.Fatalf("should not generate a session token if there is no userid")
	}
}

func TestGenerateSessionToken(t *testing.T) {

	if token := GenerateSessionToken("2341", "my secret", 3600, false); token.session == "" {
		t.Fatalf("should generate a session token")
	}

}
