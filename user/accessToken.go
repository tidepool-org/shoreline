package user

import (
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
type AccessTokenChecker struct{}

// Check the given http.Request for a valid access_token
func (a *AccessTokenChecker) Check(r *http.Request) (*TokenData, error) {

	//TODO: configuration
	const auth0TidepoolURL = "https://tidepool-dev.auth0.com/"

	configuration := auth0.NewConfiguration(
		auth0.NewJWKClient(
			auth0.JWKClientOptions{
				URI: auth0TidepoolURL + ".well-known/jwks.json",
			},
		),
		[]string{
			"open-api",
			auth0TidepoolURL + "userinfo",
		},
		auth0TidepoolURL,
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
	auth0UserID := claims["sub"].(string)
	userID := strings.Split("|", auth0UserID)[1]

	log.Println("token userID [", userID, "] ")

	return &TokenData{
		IsServer:     false,
		DurationSecs: int64(86400),
		UserId:       userID,
	}, nil
}
