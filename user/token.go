package user

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type (
	SessionToken struct {
		ID        string `json:"-" bson:"_id"`
		IsServer  bool   `json:"isServer" bson:"isServer"`
		ServerID  string `json:"-" bson:"serverId,omitempty"`
		UserID    string `json:"userId,omitempty" bson:"userId,omitempty"`
		Duration  int64  `json:"-" bson:"duration"`
		ExpiresAt int64  `json:"-" bson:"expiresAt"`
		CreatedAt int64  `json:"-" bson:"createdAt"`
		Time      int64  `json:"-" bson:"time"`
	}

	TokenData struct {
		IsServer     bool   `json:"isserver"`
		UserId       string `json:"userid"`
		DurationSecs int64  `json:"-"`
		token        string `json:"-"`
	}

	TokenConfig struct {
		Secret       string
		DurationSecs int64
	}
)

const (
	TOKEN_DURATION_KEY = "tokenduration"
)

var (
	SessionToken_error_no_userid        = errors.New("SessionToken: userId not set")
	SessionToken_error_duration_not_set = errors.New("SessionToken: duration not set")
)

func CreateSessionToken(data *TokenData, config TokenConfig) (*SessionToken, error) {
	if data.UserId == "" {
		return nil, SessionToken_error_no_userid
	}

	if data.DurationSecs == 0 {
		if data.IsServer {
			data.DurationSecs = 24 * 60 * 60
		} else {
			data.DurationSecs = config.DurationSecs
		}
	}

	now := time.Now()
	createdAt := now.Unix()
	expiresAt := now.Add(time.Duration(data.DurationSecs) * time.Second).Unix()

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	if data.IsServer {
		token.Claims["svr"] = "yes"
	} else {
		token.Claims["svr"] = "no"
	}
	token.Claims["usr"] = data.UserId
	token.Claims["dur"] = data.DurationSecs
	token.Claims["exp"] = expiresAt

	tokenString, err := token.SignedString([]byte(config.Secret))
	if err != nil {
		return nil, err
	}

	sessionToken := &SessionToken{
		ID:        tokenString,
		IsServer:  data.IsServer,
		Duration:  data.DurationSecs,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
		Time:      createdAt,
	}
	if data.IsServer {
		sessionToken.ServerID = data.UserId
	} else {
		sessionToken.UserID = data.UserId
	}

	return sessionToken, nil
}

func CreateSessionTokenAndSave(data *TokenData, config TokenConfig, store Storage) (*SessionToken, error) {
	sessionToken, err := CreateSessionToken(data, config)
	if err != nil {
		return nil, err
	}

	err = store.AddToken(sessionToken)
	if err != nil {
		return nil, err
	}

	return sessionToken, nil
}

func extractTokenDuration(r *http.Request) int64 {

	durString := r.Header.Get(TOKEN_DURATION_KEY)

	if durString != "" {
		//if there is an error we just return a duration of zero
		dur, err := strconv.ParseInt(durString, 10, 64)
		if err == nil {
			return dur
		}
	}
	return 0
}

func (tokenData *TokenData) getToken() string {
	return tokenData.token
}
