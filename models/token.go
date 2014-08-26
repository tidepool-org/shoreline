package models

import (
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"log"
	"time"
)

type (
	SessionToken struct {
		Id   string `json:"-" 	bson:"_id,omitempty"`
		Time string `json:"-" 	bson:"time"`
	}

	TokenData struct {
		UserId       string  `json:"userid"`
		IsServer     bool    `json:"isserver"`
		DurationSecs float64 `json:"-"`
		Valid        bool    `json:"-"`
	}
)

func NewSessionToken(data *TokenData, secret string) (token *SessionToken, err error) {

	const (
		HOUR_SECS = 3600
	)

	if data.UserId == "" {
		return nil, errors.New("No userId was given for the token")
	}

	if data.DurationSecs == 0 {
		data.DurationSecs = (time.Hour * 1).Seconds() //1 hour
		if data.IsServer {
			data.DurationSecs = (time.Hour * 24).Seconds() //24 hours
		}
	}
	if data.DurationSecs > 0 {
		// Create the token
		token := jwt.New(jwt.GetSigningMethod("HS256"))

		if data.IsServer {
			token.Claims["svr"] = "yes"
		} else {
			token.Claims["svr"] = "no"
		}
		token.Claims["usr"] = data.UserId
		token.Claims["dur"] = data.DurationSecs
		token.Claims["exp"] = time.Now().Add(time.Duration(data.DurationSecs/HOUR_SECS) * time.Hour).Unix()

		// Sign and get the complete encoded token as a string
		tokenString, _ := token.SignedString([]byte(secret))

		return &SessionToken{Id: tokenString, Time: time.Now().String()}, nil
	}

	return nil, errors.New("The duration for the token was 0 seconds")
}

func (t *SessionToken) unpackToken(secret string) *TokenData {

	if jwtToken, err := jwt.Parse(t.Id, func(t *jwt.Token) ([]byte, error) { return []byte(secret), nil }); err != nil {
		log.Println("unpackToken ", err)
		return nil
	} else {
		return &TokenData{
			IsServer:     jwtToken.Claims["svr"] == "yes",
			DurationSecs: jwtToken.Claims["dur"].(float64),
			UserId:       jwtToken.Claims["usr"].(string),
			Valid:        jwtToken.Valid,
		}
	}
}

func (t *SessionToken) UnpackAndVerify(secret string) *TokenData {

	if t.Id == "" {
		return nil
	}

	return t.unpackToken(secret)
	//return t.TokenData.Valid
}

func GetSessionToken(tokenString string) *SessionToken {
	return &SessionToken{Id: tokenString}
}
