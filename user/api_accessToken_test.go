package user

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

const accessToken = "one.fake.acccess_token"

var mockedAccessTokenChecker = &mockAccessTokenChecker{userID: testUser.Id}

// mockAccessToken is a test only concrete implementation of the AccessTokenInterface
type mockAccessTokenChecker struct {
	userID string
}

// Check the given http.Request for a valid access_token
func (m *mockAccessTokenChecker) Check(r *http.Request) (*TokenData, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 &&
		strings.EqualFold(auth[0:7], "BEARER ") &&
		strings.Split(auth, " ")[1] == accessToken {
		return &TokenData{
			IsServer:     false,
			DurationSecs: int64(60 * 60),
			UserId:       m.userID,
		}, nil
	}
	return nil, errors.New("invalid access_token")
}

func getAccessTokenAuthorizationHeader() http.Header {
	headers := http.Header{}
	headers.Add("Authorization", "BEARER "+accessToken)
	return headers
}

////////////////////////////////////////////////////////////////////////////////

func TestGetUserInfoNoToken(t *testing.T) {
	response := T_PerformRequestHeaders(t, "GET", "/user/"+testUser.Id, http.Header{})
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func TestGetUserInfoSessionToken(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, testUser.Id, false, testTokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: testUser.Id, Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/"+testUser.Id, headers)
	T_ExpectSuccessResponseWithJSONMap(t, response, 200)
}

func TestGetUserInfoAccessToken(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: testUser.Id, Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)
	response := T_PerformRequestHeaders(t, "GET", "/user/"+testUser.Id, getAccessTokenAuthorizationHeader())
	T_ExpectSuccessResponseWithJSONMap(t, response, 200)
}

func TestGetTokenWithInvalidAccessToken(t *testing.T) {
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, testServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/blah.blah.blah", headers)
	T_ExpectErrorResponse(t, resp, 401, "No x-tidepool-session-token was found")
}

func TestGetTokenWithAccessToken(t *testing.T) {
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, testServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/"+accessToken, headers)
	T_ExpectSuccessResponseWithJSONMap(t, resp, 200)
}

func TestGetTokenWithInvalidSessionToken(t *testing.T) {
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, testServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/not.a.session.token", headers)
	T_ExpectErrorResponse(t, resp, 401, "No x-tidepool-session-token was found")
}

func TestGetTokenWithSessionToken(t *testing.T) {
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{testUserToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, testServerToken.ID)
	resp := T_PerformRequestHeaders(t, "GET", "/token/"+testUserToken.ID, headers)
	T_ExpectSuccessResponseWithJSONMap(t, resp, 200)
}
