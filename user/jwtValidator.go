package user

import (
	"errors"
	"net/http"
	"strings"

	"github.com/tidepool-org/go-common/clients/status"
)

type JWTValidator interface {
	CheckToken(response http.ResponseWriter, request *http.Request, requiredScopes string) *TokenData
	CheckSessionToken(request *http.Request) *TokenData
	CheckAccessToken(request *http.Request, requiredScopes string) *TokenData
}

type jwtValidator struct {
	config  JWTValidatorConfig
	session *sessionValidator
	access  *auth0AccessTokenValidator
}

type JWTValidatorConfig struct {
	Auth0AccessTokenConfig
	Secret string
}

func NewJWTValidator(config JWTValidatorConfig) (*jwtValidator, error) {
	if config.Auth0AccessTokenConfig.Auth0Domain == "" {
		return nil, errors.New("Auth0 domain needs to be set")
	}
	if config.Auth0AccessTokenConfig.Auth0Audience == "" {
		return nil, errors.New("Auth0 audience needs to be set")
	}
	if config.Auth0AccessTokenConfig.Auth0PublicKey == "" {
		return nil, errors.New("Auth0 public key needs to be set")
	}
	if config.Secret == "" {
		return nil, errors.New("signing secret needs to be set")
	}
	return &jwtValidator{
		config:  config,
		session: newSessionValidator(config.Secret),
		access:  newAuth0AccessTokenValidator(config.Auth0AccessTokenConfig),
	}, nil
}

func requestURLPath(request *http.Request) string {
	if request.URL != nil {
		if strings.Contains(request.URL.Path, "/token/") {
			return request.Host + "/token/..."
		}
		return request.Host + request.URL.Path
	}
	if request.Host == "" {
		return "NOTE: internal call"
	}
	return request.Host
}

func (v *jwtValidator) CheckAccessToken(request *http.Request, requiredScopes string) *TokenData {
	logger.Println("validating access_token request", requestURLPath(request))
	data, err := v.access.validate(requiredScopes, request)
	if data != nil {
		return data
	}
	if err != nil {
		return nil
	}
	return nil
}

func (v *jwtValidator) CheckSessionToken(request *http.Request) *TokenData {
	logger.Println("validating session request", requestURLPath(request))
	data, err := v.session.validate(request)
	if data != nil {
		logger.Println("## SUCCESS ## validated as session request", requestURLPath(request))
		return data
	}
	if err != nil {
		logger.Println("## ERROR ## validating session request", requestURLPath(request), err.Error())
		return nil
	}
	return nil
}

func (v *jwtValidator) CheckToken(response http.ResponseWriter, request *http.Request, requiredScopes string) *TokenData {
	accessToken := v.CheckAccessToken(request, requiredScopes)
	if accessToken != nil {
		return accessToken
	}
	sessionToken := v.CheckSessionToken(request)
	if sessionToken != nil {
		return sessionToken
	}
	logger.Println("## WARN ## niether a valid session or access_token", requestURLPath(request))
	//TODO: yes we just return the generic http.StatusUnauthorized (401)
	//in all cases to remain consistent with existing api
	sendModelAsResWithStatus(
		response,
		status.NewStatus(http.StatusUnauthorized, STATUS_UNAUTHORIZED),
		http.StatusUnauthorized,
	)
	return nil
}
