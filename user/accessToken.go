package user

import (
	"net/http"

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
	const auth0TidepoolURL = "tidepool-dev.auth0.com"
	const tidepoolAudienceURL = "https://dev-api.tidepool.org/data"

	configuration := auth0.NewConfiguration(
		auth0.NewJWKClient(
			auth0.JWKClientOptions{
				URI: auth0TidepoolURL + ".well-known/jwks.json",
			},
		),
		[]string{
			tidepoolAudienceURL,
			auth0TidepoolURL + "/userinfo",
		},
		auth0TidepoolURL,
		jose.RS256,
	)
	validator := auth0.NewValidator(configuration)
	token, err := validator.ValidateRequest(r)
	if err != nil {
		return nil, err
	}

	claims := map[string]interface{}{}
	err = validator.Claims(r, token, &claims)
	if err != nil {
		return nil, err
	}
	userID := claims["sub"].(string)
	expiration := claims["exp"].(int64)

	return &TokenData{
		IsServer:     false,
		DurationSecs: expiration,
		UserId:       userID,
	}, nil
}
