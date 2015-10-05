package user

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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

	TokenConfig struct {
		Secret       string
		DurationSecs float64
	}
)

const (
	TOKEN_DURATION_KEY = "tokenduration"
)

var (
	SessionToken_error_no_userid        = errors.New("SessionToken: userId not set")
	SessionToken_invalid                = errors.New("SessionToken: is invalid")
	SessionToken_error_duration_not_set = errors.New("SessionToken: duration not set")
)

func CreateSessionToken(data *TokenData, config TokenConfig) (*SessionToken, error) {

	const seconds_in_one_hour = 3600

	if data.UserId == "" {
		return nil, SessionToken_error_no_userid
	}

	if data.DurationSecs == 0 {

		data.DurationSecs = config.DurationSecs //As per configuartion
		if data.IsServer {
			data.DurationSecs = (time.Hour * 24).Seconds() //24 hours
		}
	}

	token := jwt.New(jwt.GetSigningMethod("HS256"))

	if data.IsServer {
		token.Claims["svr"] = "yes"
	} else {
		token.Claims["svr"] = "no"
	}
	token.Claims["usr"] = data.UserId
	token.Claims["dur"] = data.DurationSecs
	token.Claims["exp"] = time.Now().Add(time.Duration(data.DurationSecs/seconds_in_one_hour) * time.Hour).Unix()

	tokenString, err := token.SignedString([]byte(config.Secret))

	if err != nil {
		return nil, err
	}
	return &SessionToken{Id: tokenString, Time: time.Now().Unix()}, nil
}

func CreateSessionTokenAndSave(data *TokenData, config TokenConfig, store Storage) (*SessionToken, error) {

	sessionToken, err := CreateSessionToken(data, config)
	if err != nil {
		return nil, err
	}
	err = sessionToken.Save(store)

	if err != nil {
		return nil, err
	}
	return sessionToken, nil
}

func (t *SessionToken) Save(store Storage) error {
	return store.AddToken(t)
}

func (t *SessionToken) UnpackAndVerify(secret string) (*TokenData, error) {
	if t.Id == "" {
		return nil, SessionToken_error_no_userid
	}
	return t.unpackToken(secret)
}

func GetSessionToken(tokenString string) *SessionToken {
	return &SessionToken{Id: tokenString}
}

func (t *SessionToken) unpackToken(secret string) (*TokenData, error) {

	jwtToken, err := jwt.Parse(t.Id, func(t *jwt.Token) ([]byte, error) { return []byte(secret), nil })

	if err != nil {
		return nil, err
	}

	if jwtToken.Valid == false {
		return nil, SessionToken_invalid
	}
	// only return valid unpacked tokens
	return &TokenData{
		IsServer:     jwtToken.Claims["svr"] == "yes",
		DurationSecs: jwtToken.Claims["dur"].(float64),
		UserId:       jwtToken.Claims["usr"].(string),
		Valid:        jwtToken.Valid,
	}, nil

}

func extractTokenDuration(r *http.Request) float64 {

	durString := r.Header.Get(TOKEN_DURATION_KEY)

	if durString != "" {
		//if there is an error we just return a duration of zero
		dur, err := strconv.ParseFloat(durString, 64)
		if err == nil {
			return dur
		}
	}
	return 0
}

func getUnpackedToken(tokenString, secret string) (*TokenData, error) {
	st := GetSessionToken(tokenString)
	return st.UnpackAndVerify(secret)
}

func hasServerToken(tokenString, secret string) bool {
	td, err := getUnpackedToken(tokenString, secret)
	if err != nil {
		return false
	}
	return td.IsServer
}
