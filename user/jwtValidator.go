package user

import (
	"errors"
	"log"
	"net/http"
	"strings"

	auth0 "github.com/auth0-community/go-auth0"
	jwt "github.com/dgrijalva/jwt-go"
	jose "gopkg.in/square/go-jose.v2"
)

type JWTValidator interface {
	ValidateRequest(request *http.Request) (*TokenData, error)
}

type jwtValidator struct {
	config JWTValidatorConfig
}

type JWTValidatorConfig struct {
	Auth0Domain string
	Secret      string
}

func NewJWTValidator(config JWTValidatorConfig) (*jwtValidator, error) {
	if config.Auth0Domain == "" {
		return nil, errors.New("The Auth0 domain needs to be set.")
	}
	if config.Secret == "" {
		return nil, errors.New("The signing secret needs to be set.")
	}
	return &jwtValidator{config: config}, nil
}

func getAccessToken(request *http.Request) string {
	if request != nil {
		auth := request.Header.Get("Authorization")
		if len(auth) > 7 &&
			strings.EqualFold(auth[0:7], "BEARER ") {
			return strings.Split(auth, " ")[1]
		}
	}
	return ""
}

func isSessionToken(request *http.Request) bool {
	return getSessionToken(request) != ""
}

func isAccessToken(request *http.Request) bool {
	return getAccessToken(request) != ""
}

func getSessionToken(request *http.Request) string {
	if request != nil {
		return request.Header.Get(TP_SESSION_TOKEN)
	}
	return ""
}

func makeAccessRequest(token string) *http.Request {
	request := &http.Request{Header: http.Header{}}
	request.Header.Set("authorization", "Bearer "+token)
	return request
}

func makeSessionRequest(token string) *http.Request {
	request := &http.Request{Header: http.Header{}}
	request.Header.Set(TP_SESSION_TOKEN, token)
	return request
}

func (v *jwtValidator) validateAsAccessToken(request *http.Request) (*TokenData, error) {
	configuration := auth0.NewConfiguration(
		auth0.NewJWKClient(
			auth0.JWKClientOptions{
				URI: v.config.Auth0Domain + ".well-known/jwks.json",
			},
		),
		[]string{
			"open-api",
			v.config.Auth0Domain + "userinfo",
		},
		v.config.Auth0Domain,
		jose.RS256,
	)
	validator := auth0.NewValidator(configuration)
	token, err := validator.ValidateRequest(request)
	if err != nil {
		log.Println("Error validating request: ", err)
		return nil, errors.New("Error validating access_token request")
	}

	claims := map[string]interface{}{}
	err = validator.Claims(request, token, &claims)
	if err != nil {
		log.Println("Error validating claims: ", err)
		return nil, errors.New("Error validating access_token claims")
	}

	userID := claims["sub"].(string)
	if len(userID) <= 6 && !strings.Contains(userID, "auth0|") {
		return nil, errors.New("Error invalid access_token userID")
	}
	userID = strings.TrimPrefix(userID, "auth0|")

	return &TokenData{
		IsServer:     false,
		DurationSecs: int64(86400),
		UserId:       userID,
		token:        getAccessToken(request),
	}, nil
}

func (v *jwtValidator) validateAsSessionToken(request *http.Request) (*TokenData, error) {
	sessionToken := getSessionToken(request)
	jwtToken, err := jwt.Parse(sessionToken, func(t *jwt.Token) ([]byte, error) { return []byte(v.config.Secret), nil })
	if err != nil {
		return nil, err
	}
	if !jwtToken.Valid {
		return nil, errors.New("SessionToken is invalid")
	}

	isServer := jwtToken.Claims["svr"] == "yes"
	durationSecs, ok := jwtToken.Claims["dur"].(int64)
	if !ok {
		durationSecs = int64(jwtToken.Claims["dur"].(float64))
	}
	userID := jwtToken.Claims["usr"].(string)

	return &TokenData{
		IsServer:     isServer,
		DurationSecs: durationSecs,
		UserId:       userID,
		token:        sessionToken,
	}, nil
}

func (v *jwtValidator) ValidateRequest(request *http.Request) (*TokenData, error) {
	if request == nil {
		return nil, errors.New("The request needs to be set")
	}
	//TODO: initially tokens are side-by-side so we will check both
	if isAccessToken(request) {
		tokenData, tokenError := v.validateAsAccessToken(request)
		if tokenError == nil && tokenData != nil {
			return tokenData, nil
		}
	}

	if isSessionToken(request) {
		return v.validateAsSessionToken(request)
	}
	return nil, errors.New("The request has no valid token")
}
