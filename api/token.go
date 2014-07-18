package api

import (
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
)

type SessionToken struct {
	Token string `json:"token" bson:"_id,omitempty"`
	Time  string `json:"-" bson:"time"`
}

func (t *SessionToken) UnpackToken(secret string) (*jwt.Token, error) {

	return jwt.Parse(t.Token, func(t *jwt.Token) ([]byte, error) { return []byte(secret), nil })

}

func (t *SessionToken) VerifyStoredToken(secret string) (bool, error) {

	if t.Token == "" {
		return false, errors.New("the token string is required")
	}

	token, err := t.UnpackToken(secret)
	if err != nil {
		return false, err
	}
	return token.Valid, nil
}

func GetSessionToken(header http.Header) SessionToken {
	return SessionToken{Token: header.Get("x-tidepool-session-token")}
}

func NewSessionToken(userId string, secret string, durationSeconds float64, isServer bool) (token *SessionToken, err error) {
	if userId == "" {
		return nil, errors.New("No userId was given for the token")
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

		return &SessionToken{Token: tokenString, Time: time.Now().String()}, nil
	}

	return nil, errors.New("The duration for the token was 0 seconds")
}
