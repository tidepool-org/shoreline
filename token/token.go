package token

import (
	"errors"
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
		Role         string `json:"role"`
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
	TP_SESSION_TOKEN   = "x-tidepool-session-token"
	// TP_TRACE_SESSION Session trace: uuid v4
	TP_TRACE_SESSION = "x-tidepool-trace-session"
)

var (
	SessionToken_error_no_userid        = errors.New("SessionToken: userId not set")
	SessionToken_invalid                = errors.New("SessionToken: is invalid")
	SessionToken_error_duration_not_set = errors.New("SessionToken: duration not set")
)

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
	role, ok := claims["role"].(string)
	if !ok {
		role = ""
	}

	return &TokenData{
		IsServer:     isServer,
		DurationSecs: durationSecs,
		UserId:       userId,
		Email:        email,
		Name:         name,
		Role:         role,
	}, nil
}

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

	jwt_token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := jwt_token.Claims.(jwt.MapClaims)
	if data.IsServer {
		claims["svr"] = "yes"
	} else {
		claims["svr"] = "no"
	}
	// Add claims specific to our 3rd party services
	if strings.ToUpper(data.Audience) == "ZENDESK" {
		if data.Role == "patient" {
			claims["organization"] = "Patient"
		}
		if data.Role == "hcp" {
			claims["organization"] = "Health professional"
		}
		if data.Role == "caregiver" {
			claims["organization"] = "Patient"
		}
		claims["aud"] = "zendesk"
	} else {
		claims["role"] = data.Role
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

	tokenString, err := jwt_token.SignedString([]byte(config.Secret))
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
