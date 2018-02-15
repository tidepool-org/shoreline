package user

import (
	"errors"
	"net/http"
	"testing"

	"github.com/tidepool-org/go-common/clients/status"
	"github.com/tidepool-org/go-common/tokens"
)

const testAccessToken = "one.fake.acccess_token"

var jwtValidatorTestUser = &User{Id: "334-22-999", Username: "jwtTest@new.bar", Emails: []string{"jwtTest@new.bar"}}

var mockedJWTValidator = &mockJWTValidator{
	userID: jwtValidatorTestUser.Id,
	config: JWTValidatorConfig{
		Auth0AccessTokenConfig: Auth0AccessTokenConfig{
			Auth0PublicKey: "",
			Auth0Domain:    "",
			Auth0Audience:  "",
		},
		Secret: testAPIConfig.Secret,
	},
}

type mockJWTValidator struct {
	userID string
	config JWTValidatorConfig
}

func (m *mockJWTValidator) CheckToken(response http.ResponseWriter, request *http.Request, requiredScopes string) *TokenData {
	if tokens.IsBearerToken(request) {
		if tokens.GetBearerToken(request) == testAccessToken {
			return &TokenData{
				IsServer:     false,
				DurationSecs: int64(60 * 60),
				UserId:       m.userID,
				token:        tokens.GetBearerToken(request),
			}
		}
	}
	if tokens.IsSessionToken(request) {
		token, err := responsableStore.FindTokenByID(tokens.GetSessionToken(request))
		if err == nil && token != nil {

			id := token.UserID
			if token.IsServer {
				id = token.ServerID
			}

			return &TokenData{
				IsServer:     token.IsServer,
				DurationSecs: token.Duration,
				UserId:       id,
				token:        token.ID,
			}
		}
	}
	//TODO: yes we just return the generic http.StatusUnauthorized (401) in all cases
	sendModelAsResWithStatus(response, status.NewStatus(http.StatusUnauthorized, STATUS_UNAUTHORIZED), http.StatusUnauthorized)
	return nil
}

func (m *mockJWTValidator) CheckAccessToken(request *http.Request, requiredScopes string) *TokenData {
	if tokens.GetBearerToken(request) == testAccessToken {
		return &TokenData{
			IsServer:     false,
			DurationSecs: int64(60 * 60),
			UserId:       m.userID,
			token:        tokens.GetBearerToken(request),
		}
	}
	return nil
}

func (m *mockJWTValidator) CheckSessionToken(request *http.Request) *TokenData {
	session := tokens.GetSessionToken(request)
	if session != "" {
		token, err := responsableStore.FindTokenByID(session)
		if err == nil && token != nil {

			id := token.UserID
			if token.IsServer {
				id = token.ServerID
			}
			return &TokenData{
				IsServer:     token.IsServer,
				DurationSecs: token.Duration,
				UserId:       id,
				token:        token.ID,
			}
		}
	}
	return nil
}

func makeBearerHeader() http.Header {
	headers := http.Header{}
	headers.Add("Authorization", "BEARER "+testAccessToken)
	return headers
}

////////////////////////////////////////////////////////////////////////////////

func TestGetUserInfoNoToken(t *testing.T) {
	response := T_PerformRequestHeaders(t, "GET", "/user/"+jwtValidatorTestUser.Id, http.Header{})
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func TestGetUserInfoSessionToken(t *testing.T) {
	jwtSessionToken := T_CreateSessionToken(t, jwtValidatorTestUser.Id, false, testTokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{jwtSessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: jwtValidatorTestUser.Id, Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(tokens.TidepoolSessionTokenName, jwtSessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/"+jwtValidatorTestUser.Id, headers)
	T_ExpectSuccessResponseWithJSONMap(t, response, 200)
}

func TestGetUserInfoAccessToken(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: jwtValidatorTestUser.Id, Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)
	response := T_PerformRequestHeaders(t, "GET", "/user/"+jwtValidatorTestUser.Id, makeBearerHeader())
	T_ExpectSuccessResponseWithJSONMap(t, response, 200)
}

func TestGetTokenWithInvalidAccessToken(t *testing.T) {
	jwtServerToken := T_CreateSessionToken(t, "shoreline-jwt", true, testTokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{jwtServerToken, nil}, {nil, errors.New("no token")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(tokens.TidepoolSessionTokenName, jwtServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/blah.blah.blah", headers)
	T_ExpectErrorResponse(t, resp, 401, STATUS_UNAUTHORIZED)
}

func TestGetTokenWithAccessToken(t *testing.T) {
	jwtServerToken := T_CreateSessionToken(t, "shoreline-jwt", true, testTokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{jwtServerToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(tokens.TidepoolSessionTokenName, jwtServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/"+testAccessToken+"/scopes:here", headers)
	T_ExpectSuccessResponseWithJSONMap(t, resp, 200)
}

func TestGetTokenWithInvalidSessionToken(t *testing.T) {
	jwtServerToken := T_CreateSessionToken(t, "shoreline-jwt", true, testTokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{jwtServerToken, nil}, {nil, errors.New("no token")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(tokens.TidepoolSessionTokenName, jwtServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/not.a.session.token", headers)
	T_ExpectErrorResponse(t, resp, 401, STATUS_UNAUTHORIZED)
}

func TestGetTokenWithSessionToken(t *testing.T) {
	jwtServerToken := T_CreateSessionToken(t, "shoreline-jwt", true, testTokenDuration)
	jwtUserToken := T_CreateSessionToken(t, jwtValidatorTestUser.Id, false, testTokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{jwtServerToken, nil}, {jwtUserToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(tokens.TidepoolSessionTokenName, jwtServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/"+jwtUserToken.ID, headers)
	t.Log("response: ", resp)
	T_ExpectSuccessResponseWithJSONMap(t, resp, 200)
}
