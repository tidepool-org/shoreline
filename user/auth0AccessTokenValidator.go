package user

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/tidepool-org/go-common/tokens"

	"github.com/auth0-community/go-auth0"
	"gopkg.in/square/go-jose.v2"
)

type Auth0AccessTokenConfig struct {
	Auth0Domain    string
	Auth0Audience  string
	Auth0PublicKey string
}

type auth0AccessTokenValidator struct {
	config Auth0AccessTokenConfig
}

func makeBearerRequest(token string) *http.Request {
	request := &http.Request{Header: http.Header{}}
	request.Header.Set("authorization", token)
	return request
}

func validScopes(requiredScopes []string, clientScopes string) bool {
	for requiredScope := range requiredScopes {
		if !strings.Contains(clientScopes, requiredScopes[requiredScope]) {
			return false
		}
	}
	return true
}

func hostedAuth0Validator(config Auth0AccessTokenConfig) *auth0.JWTValidator {

	keyProvider := auth0.NewJWKClient(
		auth0.JWKClientOptions{URI: config.Auth0Domain + ".well-known/jwks.json"},
	)

	configuration := auth0.NewConfiguration(
		keyProvider,
		[]string{config.Auth0Audience, config.Auth0Domain + "userinfo"},
		config.Auth0Domain,
		jose.RS256,
	)
	return auth0.NewValidator(configuration)
}

func (a *auth0AccessTokenValidator) localAuth0Validator() (*auth0.JWTValidator, error) {

	data, err := ioutil.ReadFile(a.config.Auth0PublicKey)
	if err != nil {
		logger.Println("Error loading the public key", err)
		return nil, errors.New("Error loading the public key")
	}

	input := data

	block, _ := pem.Decode([]byte(data))
	if block != nil {
		input = block.Bytes
	}

	var provider auth0.SecretProvider
	publicKey, err0 := x509.ParsePKIXPublicKey(input)
	if err0 == nil {
		provider = auth0.NewKeyProvider(publicKey)
	} else {
		logger.Println("Error ParsePKIXPublicKey", err0)
		cert, err1 := x509.ParseCertificate(input)
		if err1 != nil {
			logger.Println("Error loading the public key", err1)
			return nil, errors.New("Error loading the public key")
		}
		provider = auth0.NewKeyProvider(cert)
	}

	configuration := auth0.NewConfiguration(
		provider,
		[]string{a.config.Auth0Audience, a.config.Auth0Domain + "userinfo"},
		a.config.Auth0Domain,
		jose.RS256,
	)
	return auth0.NewValidator(configuration), nil
}

func newAuth0AccessTokenValidator(config Auth0AccessTokenConfig) *auth0AccessTokenValidator {
	return &auth0AccessTokenValidator{
		config: config,
	}
}

func (a *auth0AccessTokenValidator) validate(requiredScopes string, request *http.Request) (*TokenData, error) {

	// localValidator, err := localAuth0Validator(a.config)
	// if err != nil {
	// 	log.Println("Error creating localAuth0Validator: ", err)
	// 	return nil, errors.New("Error creating validator")
	// }
	// token, err := localValidator.ValidateRequest(request)
	// if err != nil {
	// 	log.Println("Error validating request: ", err)
	// 	return nil, errors.New("Error validating request")
	// }
	//validate with Auth0
	auth0Validator := hostedAuth0Validator(a.config)
	token, err := auth0Validator.ValidateRequest(request)
	logger.Println("Validated via auth0: ", token)
	if err != nil {
		logger.Println("Error validating with Auth0: ", err)
		return nil, errors.New("Error validating with Auth0")
	}
	//test claims
	claims := map[string]interface{}{}
	err = auth0Validator.Claims(request, token, &claims)
	if err != nil {
		logger.Println("Error validating claims: ", err)
		return nil, errors.New("Error validating claims")
	}
	//check scopes
	if claims["scopes"] != nil {
		clientScopes := claims["scopes"].(string)
		if !validScopes(strings.Split(requiredScopes, " "), clientScopes) {
			logger.Printf("required scopes [%s] allowed scopes [%s] when trying to access `%s %s`", requiredScopes, clientScopes, request.Host, request.URL.Path)
		}
	}

	//get userID from claims
	if claims["sub"] == nil {
		return nil, errors.New("Error finding userID")
	}
	userID := claims["sub"].(string)
	if len(userID) <= 6 && !strings.Contains(userID, "auth0|") {
		return nil, errors.New("Error invalid userID")
	}

	return &TokenData{
		IsServer:     false,
		DurationSecs: int64(86400),
		UserId:       strings.TrimPrefix(userID, "auth0|"),
		token:        tokens.GetBearerToken(request),
	}, nil
}
