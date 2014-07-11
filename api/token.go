package api

import (
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
)

type (
	Token struct {
		session string
	}
)

func UnpackToken() *Token {
	return &Token{}
}

func GetSessionToken(header http.Header) *Token {
	return &Token{session: header.Get("x-tidepool-session-token")}
}

func GenerateSessionToken(userId string, secret string, durationSeconds float64, isServer bool) *Token {
	if userId == "" {
		return &Token{}
	}

	if durationSeconds == 0 {
		durationSeconds = time.Duration.Seconds(1 * time.Hour) //1 hour
		if isServer {
			durationSeconds = time.Duration.Seconds(24 * time.Hour) //24 hours
		}
	}
	if durationSeconds > 0 {
		// Create the token
		token := jwt.New(jwt.GetSigningMethod("HS256"))
		// Set some claims
		token.Claims["svr"] = "no"
		if isServer {
			token.Claims["svr"] = "yes"
		}
		token.Claims["usr"] = userId
		token.Claims["dur"] = durationSeconds
		token.Claims["exp"] = time.Now().Add(time.Duration(durationSeconds)).Unix()

		// Sign and get the complete encoded token as a string
		tokenString, _ := token.SignedString([]byte(secret))

		return &Token{session: tokenString}
	}

	return &Token{}
}

func (t *Token) Verify() bool {
	return false
}

func (t *Token) Upsert() {

}
