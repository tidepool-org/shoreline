package user

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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
	}

	TokenConfig struct {
		EncodeKey    string
		DurationSecs int64
		DecodeKey    string
		Audience     string
		Issuer       string
		Algorithm    string
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

	token := jwt.New(jwt.GetSigningMethod(config.Algorithm))
	if data.IsServer {
		token.Claims["svr"] = "yes"
	} else {
		token.Claims["svr"] = "no"
	}
	token.Claims["usr"] = data.UserId
	token.Claims["dur"] = data.DurationSecs
	token.Claims["exp"] = expiresAt
	if config.Issuer == "" {
		token.Claims["iss"] = "localhost"
	} else {
		token.Claims["iss"] = config.Issuer
	}
	token.Claims["sub"] = data.UserId
	if config.Audience == "" {
		token.Claims["aud"] = "localhost"
	} else {
		token.Claims["aud"] = config.Audience
	}
	token.Claims["iat"] = createdAt

	tokenString, err := token.SignedString([]byte(config.EncodeKey))
	if err != nil {
		log.Print("failed to sign")
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

	_, err = UnpackSessionTokenAndVerify(sessionToken.ID, config)
	if err != nil {
		log.Printf("failed to verify new session token %v", sessionToken.ID)
		log.Printf("config %v", config)
		return nil, err
	}

	err = store.AddToken(sessionToken)
	if err != nil {
		return nil, err
	}

	return sessionToken, nil
}

func UnpackSessionTokenAndVerify(id string, tokenConfigs ...TokenConfig) (*TokenData, error) {
	if id == "" {
		return nil, SessionToken_error_no_userid
	}

	var jwtToken *jwt.Token
	var err error
	for _, tokenConfig := range tokenConfigs {
		jwtToken, err = jwt.Parse(id, func(t *jwt.Token) ([]byte, error) { return []byte(tokenConfig.DecodeKey), nil })
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if !jwtToken.Valid {
		return nil, SessionToken_invalid
	}

	isServer := jwtToken.Claims["svr"] == "yes"
	durationSecs, ok := jwtToken.Claims["dur"].(int64)
	if !ok {
		durationSecs = int64(jwtToken.Claims["dur"].(float64))
	}
	userId := jwtToken.Claims["usr"].(string)

	return &TokenData{
		IsServer:     isServer,
		DurationSecs: durationSecs,
		UserId:       userId,
	}, nil
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

func hasServerToken(tokenString string, tokenConfigs ...TokenConfig) bool {
	td, err := UnpackSessionTokenAndVerify(tokenString, tokenConfigs...)
	if err != nil {
		return false
	}
	return td.IsServer
}
