package user

import (
	"errors"
	"log"
	"net/http"
	"strings"

	auth0 "github.com/auth0-community/go-auth0"
	jose "gopkg.in/square/go-jose.v2"
)

// AccessTokenCheckerInterface can the access_token on a request.
type AccessTokenCheckerInterface interface {
	Check(r *http.Request) (*TokenData, error)
}

// AccessTokenChecker is a concrete implementation of the AccessTokenCheckerInterface
type AccessTokenChecker struct {
	// Auth0Domain that you use e.g. https://YOUR_DOMAIN.auth0.com/
	Auth0Domain string
}

// Check the given http.Request for a valid access_token
func (a *AccessTokenChecker) Check(r *http.Request) (*TokenData, error) {

	if a.Auth0Domain == "" {
		return nil, errors.New("The Auth0 domain needs to be set.")
	}

	configuration := auth0.NewConfiguration(
		auth0.NewJWKClient(
			auth0.JWKClientOptions{
				URI: a.Auth0Domain + ".well-known/jwks.json",
			},
		),
		[]string{
			"open-api",
			a.Auth0Domain + "userinfo",
		},
		a.Auth0Domain,
		jose.RS256,
	)
	validator := auth0.NewValidator(configuration)
	token, err := validator.ValidateRequest(r)
	if err != nil {
		log.Println("Error validating request: ", err)
		return nil, err
	}

	claims := map[string]interface{}{}
	err = validator.Claims(r, token, &claims)
	if err != nil {
		log.Println("Error validating claims: ", err)
		return nil, err
	}

	userID := claims["sub"].(string)
	if len(userID) > 6 && strings.Contains(userID, "auth0|") {
		userID = strings.Split(userID, "auth0|")[1]
	}

	return &TokenData{
		IsServer:     false,
		DurationSecs: int64(86400),
		UserId:       userID,
	}, nil
}
