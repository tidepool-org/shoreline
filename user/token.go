package user

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
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
		Email        string `json:"email"`
		Name         string `json:"name"`
		IsClinic     bool   `json:"isclinic"`
		DurationSecs int64  `json:"-"`
		Audience     string `json:"audience"`
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

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	if data.IsServer {
		claims["svr"] = "yes"
	} else {
		claims["svr"] = "no"
	}
	// Add claims specific to our 3rd party services
	if strings.ToUpper(data.Audience) == "ZENDESK" {
		if data.IsClinic {
			claims["organization"] = "Psad"
		} else {
			claims["organization"] = "Patient"
			claims["tags"] = "patient"
		}
		claims["aud"] = "zendesk"
	}
	claims["usr"] = data.UserId
	if data.Name != "" {
		claims["name"] = data.Name
	}
	if data.Email != "" {
		claims["email"] = data.Email
	}

	claims["dur"] = data.DurationSecs
	claims["exp"] = expiresAt
	claims["iat"] = createdAt
	claims["jti"] = uuid.New()

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

func UnpackSessionTokenAndVerify(id string, secret string) (*TokenData, error) {
	if id == "" {
		return nil, SessionToken_error_no_userid
	}

	jwtToken, err := jwt.Parse(id, func(t *jwt.Token) (interface{}, error) { return []byte(secret), nil })
	if err != nil {
		return nil, err
	}
	if !jwtToken.Valid {
		return nil, SessionToken_invalid
	}

	claims := jwtToken.Claims.(jwt.MapClaims)
	isServer := claims["svr"] == "yes"
	durationSecs, ok := claims["dur"].(int64)
	if !ok {
		durationSecs = int64(claims["dur"].(float64))
	}
	userId := claims["usr"].(string)

	email, ok := claims["email"].(string)
	if !ok {
		email = ""
	}
	name, ok := claims["name"].(string)
	if !ok {
		name = email
	}

	return &TokenData{
		IsServer:     isServer,
		DurationSecs: durationSecs,
		UserId:       userId,
		Email:        email,
		Name:         name,
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

func hasServerToken(tokenString, secret string) bool {
	td, err := UnpackSessionTokenAndVerify(tokenString, secret)
	if err != nil {
		return false
	}
	return td.IsServer
}
