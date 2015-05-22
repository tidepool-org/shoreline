package user

import (
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"strconv"
	"time"
)

type (
	SessionToken struct {
		Id   string `json:"-" 	bson:"_id,omitempty"`
		Time int64  `json:"-" 	bson:"time"`
	}

	TokenData struct {
		UserId       string  `json:"userid"`
		IsServer     bool    `json:"isserver"`
		DurationSecs float64 `json:"-"`
		Valid        bool    `json:"-"`
	}
)

const (
	TOKEN_DURATION_KEY = "tokenduration"
)

func CreateSessionToken(data *TokenData, secret string) (token *SessionToken, err error) {

	const seconds_in_one_hour = 3600

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
		token.Claims["exp"] = time.Now().Add(time.Duration(data.DurationSecs/seconds_in_one_hour) * time.Hour).Unix()

		// Sign and get the complete encoded token as a string
		tokenString, _ := token.SignedString([]byte(secret))

		return &SessionToken{Id: tokenString, Time: time.Now().Unix()}, nil
	}

	return nil, errors.New("The duration for the token was 0 seconds")
}

func CreateSessionTokenAndSave(data *TokenData, secret string, store Storage) (token *SessionToken, err error) {

	if sessionToken, err := CreateSessionToken(
		data,
		secret,
	); err != nil {
		log.Print(USER_API_PREFIX, "error creating new SessionToken", err.Error())
		return nil, err
	} else {
		if err = sessionToken.Save(store); err != nil {
			log.Print(USER_API_PREFIX, "error saving SessionToken", err.Error())
			return nil, err
		} else {
			return sessionToken, nil
		}
	}
}

func (t *SessionToken) Save(store Storage) error {
	if err := store.AddToken(t); err != nil {
		log.Print(USER_API_PREFIX, "error saving SessionToken", err.Error())
		return err
	}
	return nil
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

func (t *SessionToken) unpackToken(secret string) *TokenData {

	if jwtToken, err := jwt.Parse(t.Id, func(t *jwt.Token) ([]byte, error) { return []byte(secret), nil }); err != nil {
		log.Print(USER_API_PREFIX, "unpackToken ", err)
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

func extractTokenDuration(r *http.Request) (dur float64) {

	durString := r.Header.Get(TOKEN_DURATION_KEY)

	if durString != "" {
		log.Printf(USER_API_PREFIX+"tokenDuration: given duration [%s]", durString)
		dur, _ = strconv.ParseFloat(durString, 64)
		log.Printf(USER_API_PREFIX+"tokenDuration: set to [%f]", dur)
		return dur
	}

	log.Print(USER_API_PREFIX, "tokenDuration: was not set so setting to zero")
	return 0
}

func getUnpackedToken(tokenString, secret string) *TokenData {
	if st := GetSessionToken(tokenString); st.Id != "" {
		if td := st.UnpackAndVerify(secret); td != nil && td.Valid == true {
			return td
		}
	}
	return nil
}

func hasServerToken(tokenString, secret string) bool {

	if td := getUnpackedToken(tokenString, secret); td != nil {
		return td.IsServer
	}
	return false
}
