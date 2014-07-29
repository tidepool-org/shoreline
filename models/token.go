package models

import (
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

type (
	SessionToken struct {
		Token     string    `json:"-" 	bson:"_id,omitempty"`
		Time      string    `json:"-" 	bson:"time"`
		TokenData TokenData `json:"-"`
	}

	TokenData struct {
		UserId   string  `json:"userid"`
		IsServer bool    `json:"isserver"`
		Duration float64 `json:"-"`
		Valid    bool    `json:"-"`
	}
)

func NewSessionToken(data *TokenData, secret string) (token *SessionToken, err error) {

	if data.UserId == "" {
		return nil, errors.New("No userId was given for the token")
	}

	if data.Duration == 0 {
		data.Duration = time.Duration.Seconds(1 * time.Hour) //1 hour
		if data.IsServer {
			data.Duration = time.Duration.Seconds(24 * time.Hour) //24 hours
		}
	}
	if data.Duration > 0 {
		// Create the token
		token := jwt.New(jwt.GetSigningMethod("HS256"))
		// Set some claims
		token.Claims["svr"] = "no"
		if data.IsServer {
			token.Claims["svr"] = "yes"
		}
		token.Claims["usr"] = data.UserId
		token.Claims["dur"] = data.Duration
		token.Claims["exp"] = time.Now().Add(time.Duration(data.Duration)).Unix()

		// Sign and get the complete encoded token as a string
		tokenString, _ := token.SignedString([]byte(secret))

		return &SessionToken{Token: tokenString, Time: time.Now().String()}, nil
	}

	return nil, errors.New("The duration for the token was 0 seconds")
}

func (t *SessionToken) unpackToken(secret string) {

	if jwtToken, err := jwt.Parse(t.Token, func(t *jwt.Token) ([]byte, error) { return []byte(secret), nil }); err != nil {
		return
	} else {

		t.TokenData = TokenData{
			IsServer: jwtToken.Claims["svr"] == "yes",
			Duration: jwtToken.Claims["dur"].(float64),
			UserId:   jwtToken.Claims["usr"].(string),
			Valid:    jwtToken.Valid,
		}
		return
	}
}

func (t *SessionToken) Verify(secret string) bool {

	if t.Token == "" {
		return false
	}

	t.unpackToken(secret)
	return t.TokenData.Valid
}

func GetSessionToken(tokenString string) *SessionToken {
	return &SessionToken{Token: tokenString}
}
