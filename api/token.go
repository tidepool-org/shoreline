package api

import (
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
	"time"
)

type SessionToken struct {
	tokenString string
}

func (t *SessionToken) UnpackToken(secret string) (*jwt.Token, error) {

	return jwt.Parse(t.tokenString, func(t *jwt.Token) ([]byte, error) { return []byte(secret), nil })

}

func (t *SessionToken) VerifyStoredToken(secret string) (bool, error) {

	if t.tokenString == "" {
		return false, errors.New("the token string is required")
	}

	token, err := t.UnpackToken(secret)
	if err != nil {
		return false, err
	}
	return token.Valid, nil
}

func GetSessionToken(header http.Header) SessionToken {
	return SessionToken{tokenString: header.Get("x-tidepool-session-token")}
}

func GenerateSessionToken(userId string, secret string, durationSeconds float64, isServer bool) (SessionToken, error) {
	if userId == "" {
		return SessionToken{}, errors.New("No userId was given for the token")
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

		return SessionToken{tokenString: tokenString}, nil
	}

	return SessionToken{}, errors.New("The duration for the token was 0 seconds")
}
