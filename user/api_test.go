package user

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/version"

	"github.com/tidepool-org/shoreline/oauth2"
)

const (
	THE_SECRET   = "This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy"
	MAKE_IT_FAIL = true
)

type (
	MockOAuth struct{}
)

var (
	NO_PARAMS      = map[string]string{}
	TOKEN_DURATION = int64(3600)
	FAKE_CONFIG    = ApiConfig{
		Secrets: []Secret{Secret{Secret: "default", Pass: "This needs to be the same secret everywhere. YaHut75NsK1f9UKUXuWqxNN0RUwHFBCy"},
			Secret{Secret: "product_website", Pass: "Not so secret"}},
		Secret:                      "This is a local API secret for everyone. BsscSHqSHiwrBMJsEGqbvXiuIUPAjQXU",
		TokenDurationSecs:           TOKEN_DURATION,
		LongTermKey:                 "thelongtermkey",
		Salt:                        "a mineral substance composed primarily of sodium chloride",
		MaxFailedLogin:              5,
		DelayBeforeNextLoginAttempt: 10,
		MaxConcurrentLogin:          100,
		VerificationSecret:          "",
		ClinicDemoUserID:            "00000000",
	}
	/*
	 * users and tokens
	 */
	TOKEN_CONFIG  = TokenConfig{DurationSecs: FAKE_CONFIG.TokenDurationSecs, Secret: FAKE_CONFIG.Secret}
	USR           = &User{Id: "123-99-100", Username: "test@new.bar", Emails: []string{"test@new.bar"}}
	USR_TOKEN, _  = CreateSessionToken(&TokenData{UserId: USR.Id, IsServer: false, DurationSecs: TOKEN_DURATION}, TOKEN_CONFIG)
	SRVR_TOKEN, _ = CreateSessionToken(&TokenData{UserId: "shoreline", IsServer: true, DurationSecs: TOKEN_DURATION}, TOKEN_CONFIG)
	/*
	 * basics setup
	 */
	rtr = mux.NewRouter()
	/*
	 * expected path
	 */
	mockStore = NewMockStoreClient(FAKE_CONFIG.Salt, false, false)
	shoreline = InitApi(FAKE_CONFIG, mockStore)
	/*
	 *
	 */
	mockNoDupsStore = NewMockStoreClient(FAKE_CONFIG.Salt, true, false)
	shorelineNoDups = InitApi(FAKE_CONFIG, mockNoDupsStore)
	/*
	 * failure path
	 */
	mockStoreFails = NewMockStoreClient(FAKE_CONFIG.Salt, false, MAKE_IT_FAIL)
	shorelineFails = InitApi(FAKE_CONFIG, mockStoreFails)

	responsableStore      = NewResponsableMockStoreClient()
	responsableGatekeeper = NewResponsableMockGatekeeper()
	responsableShoreline  = InitShoreline(FAKE_CONFIG, responsableStore, responsableGatekeeper)
)

func InitShoreline(config ApiConfig, store Storage, perms clients.Gatekeeper) *Api {
	api := InitApi(config, store)
	api.AttachPerms(perms)
	return api
}

////////////////////////////////////////////////////////////////////////////////

func T_CreateAuthorization(t *testing.T, email string, password string) string {
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", email, password))))
}

func T_CreateSessionToken(t *testing.T, userId string, isServer bool, duration int64) *SessionToken {
	sessionToken, err := CreateSessionToken(&TokenData{UserId: userId, IsServer: isServer, DurationSecs: duration}, TOKEN_CONFIG)
	if err != nil {
		t.Fatalf("Error creating session token: %#v", err)
	}
	return sessionToken
}

func T_PerformRequest(t *testing.T, method string, url string) *httptest.ResponseRecorder {
	return T_PerformRequestBodyHeaders(t, method, url, "", nil)
}

func T_PerformRequestBody(t *testing.T, method string, url string, body string) *httptest.ResponseRecorder {
	return T_PerformRequestBodyHeaders(t, method, url, body, nil)
}

func T_PerformRequestHeaders(t *testing.T, method string, url string, headers http.Header) *httptest.ResponseRecorder {
	return T_PerformRequestBodyHeaders(t, method, url, "", headers)
}

func T_PerformRequestBodyHeaders(t *testing.T, method string, url string, body string, headers http.Header) *httptest.ResponseRecorder {
	request, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to create new request with error %#v", err)
	} else if request == nil {
		t.Fatalf("Failure to request new request")
	}
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}

	response := httptest.NewRecorder()
	router := mux.NewRouter()
	responsableShoreline.SetHandlers("", router)
	router.ServeHTTP(response, request)
	return response
}

func T_ExpectErrorResponse(t *testing.T, response *httptest.ResponseRecorder, expectedCode int, expectedReason string) {
	if response.Code != expectedCode {
		t.Fatalf("Unexpected response status code: %d", response.Code)
	}

	if contentType := response.HeaderMap["Content-Type"][0]; contentType != "application/json" {
		t.Fatalf("Unexpected response content type: %s", contentType)
	}

	if response.Body == nil {
		t.Fatalf("Unexpected nil response body")
	}

	var errorResponse map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&errorResponse); err != nil {
		t.Fatalf("Error parsing response body: %#v", err)
	}

	if code := errorResponse["code"].(float64); int(code) != expectedCode {
		t.Fatalf("Unexpected response error code: %#v", code)
	}
	if reason := errorResponse["reason"].(string); reason != expectedReason {
		t.Fatalf("Unexpected response error reason: %#v", reason)
	}
}

func T_ExpectSuccessResponse(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) string {
	if response.Code != expectedCode {
		t.Fatalf("Unexpected response status code: %d", response.Code)
	}

	var successResponse string
	if response.Body != nil {
		var buffer bytes.Buffer
		buffer.ReadFrom(response.Body)
		successResponse = buffer.String()
	}
	return successResponse
}

func T_ExpectSuccessResponseWithJSON(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) {
	if response.Code != expectedCode {
		t.Fatalf("Unexpected response status code: %d", response.Code)
	}

	if contentTypes := response.HeaderMap["Content-Type"]; len(contentTypes) == 0 {
		t.Fatalf("Unexpected response without content type")
	} else if contentType := contentTypes[0]; contentType != "application/json" {
		t.Fatalf("Unexpected response content type: %s", contentType)
	}

	if response.Body == nil {
		t.Fatalf("Unexpected nil response body")
	}
}

func T_ExpectSuccessResponseWithJSONArray(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) []interface{} {
	T_ExpectSuccessResponseWithJSON(t, response, expectedCode)

	var successResponse []interface{}
	if err := json.NewDecoder(response.Body).Decode(&successResponse); err != nil {
		t.Fatalf("Error parsing response body: %#v", err)
	}
	return successResponse
}

func T_ExpectSuccessResponseWithJSONMap(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) map[string]interface{} {
	T_ExpectSuccessResponseWithJSON(t, response, expectedCode)

	var successResponse map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&successResponse); err != nil {
		t.Fatalf("Error parsing response body: %#v", err)
	}
	return successResponse
}

func T_ExpectElementMatch(t *testing.T, actual map[string]interface{}, key string, pattern string, remove bool) {
	if raw, ok := actual[key]; !ok {
		t.Fatalf("Missing expected element with key '%s' in: %#v", key, actual)
	} else if value, ok := raw.(string); !ok {
		t.Fatalf("Missing expected element with key '%s' is not a string", key)
	} else if matched, _ := regexp.MatchString(pattern, value); !matched {
		t.Fatalf("Expected element with key '%s' and value '%s' did not match pattern: %s", key, value, pattern)
	}
	if remove {
		delete(actual, key)
	}
}

func T_ExpectEqualsArray(t *testing.T, actual []interface{}, expected []interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Actual %#v does not match expected %#v", actual, expected)
	}
}

func T_ExpectEqualsMap(t *testing.T, actual map[string]interface{}, expected map[string]interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Actual %#v does not match expected %#v", actual, expected)
	}
}

func T_ExpectResponsablesEmpty(t *testing.T) {
	if responsableStore.HasResponses() {
		if len(responsableStore.PingResponses) > 0 {
			t.Logf("PingResponses still available")
		}
		if len(responsableStore.UpsertUserResponses) > 0 {
			t.Logf("UpsertUserResponses still available")
		}
		if len(responsableStore.FindUsersResponses) > 0 {
			t.Logf("FindUsersResponses still available")
		}
		if len(responsableStore.FindUserResponses) > 0 {
			t.Logf("FindUserResponses still available")
		}
		if len(responsableStore.RemoveUserResponses) > 0 {
			t.Logf("RemoveUserResponses still available")
		}
		if len(responsableStore.AddTokenResponses) > 0 {
			t.Logf("AddTokenResponses still available")
		}
		if len(responsableStore.FindTokenByIDResponses) > 0 {
			t.Logf("FindTokenByIDResponses still available")
		}
		if len(responsableStore.RemoveTokenByIDResponses) > 0 {
			t.Logf("RemoveTokenByIDResponses still available")
		}
		responsableStore.Reset()
		t.Fail()
	}
	if responsableGatekeeper.HasResponses() {
		if len(responsableGatekeeper.UserInGroupResponses) > 0 {
			t.Logf("UserInGroupResponses still available")
		}
		if len(responsableGatekeeper.UsersInGroupResponses) > 0 {
			t.Logf("UsersInGroupResponses still available")
		}
		if len(responsableGatekeeper.SetPermissionsResponses) > 0 {
			t.Logf("SetPermissionsResponses still available")
		}
		responsableGatekeeper.Reset()
		t.Fail()
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestGetStatus_StatusOk(t *testing.T) {

	request, _ := http.NewRequest("GET", "/status", nil)
	response := httptest.NewRecorder()

	version.ReleaseNumber = "1.2.3"
	version.FullCommit = "e0c73b95646559e9a3696d41711e918398d557fb"

	shoreline.SetHandlers("", rtr)

	shoreline.GetStatus(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Resp given [%d] expected [%d] ", response.Code, http.StatusOK)
	}
	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != "{\"status\":{\"code\":200,\"reason\":\"OK\"},\"version\":\"1.2.3+e0c73b95646559e9a3696d41711e918398d557fb\"}" {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), "{\"status\":{\"code\":200,\"reason\":\"OK\"},\"version\":\"1.2.3+e0c73b95646559e9a3696d41711e918398d557fb\"}")
	}

}

func TestGetStatus_StatusInternalServerError(t *testing.T) {

	request, _ := http.NewRequest("GET", "/status", nil)
	response := httptest.NewRecorder()

	version.ReleaseNumber = "1.2.3"
	version.FullCommit = "e0c73b95646559e9a3696d41711e918398d557fb"

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.GetStatus(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("Resp given [%d] expected [%d] ", response.Code, http.StatusInternalServerError)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != "{\"status\":{\"code\":500,\"reason\":\"Session failure\"},\"version\":\"1.2.3+e0c73b95646559e9a3696d41711e918398d557fb\"}" {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), "{\"status\":{\"code\":500,\"reason\":\"Session failure\"},\"version\":\"1.2.3+e0c73b95646559e9a3696d41711e918398d557fb\"}")
	}

}

////////////////////////////////////////////////////////////////////////////////

func Test_GetUsers_Error_MissingSessionToken(t *testing.T) {
	response := T_PerformRequest(t, "GET", "/users?role=clinic")
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUsers_Error_TokenError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{nil, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users?role=clinic", headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUsers_Error_NotServerToken(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users?role=clinic", headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUsers_Error_InvalidRole(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users?role=invalid", headers)
	T_ExpectErrorResponse(t, response, 400, "The role specified is invalid")
}

func Test_GetUsers_Error_NoQuery(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users", headers)
	T_ExpectErrorResponse(t, response, 400, "A query must be specified")
}

func Test_GetUsers_Error_InvalidQuery(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users?yolo=swag", headers)
	T_ExpectErrorResponse(t, response, 400, "Unknown query parameter")
}

func Test_GetUsers_Error_FindUsersWithIdsError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersWithIdsResponses = []FindUsersWithIdsResponse{{[]*User{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users?id=abcdef1234", headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func FindUsersWithIds(t *testing.T, userIds []string) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest("GET", "/users?id="+strings.Join(userIds, ","), nil)
	r.Header.Set(TP_SESSION_TOKEN, SRVR_TOKEN.ID)
	if err != nil {
		t.Fatal(err)
	}

	shoreline.GetUsers(rr, r)

	rs := rr.Result()

	if rs.StatusCode != http.StatusOK {
		t.Fatalf("want %d; got %d", http.StatusOK, rs.StatusCode)
	}

	defer rs.Body.Close()
	body, err := ioutil.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}

	var users []User
	json.Unmarshal(body, &users)
	if users != nil && len(users) != len(userIds) {
		t.Fatalf("Expected %d user(s) with IDs '%#v'. Got %#v", len(userIds), userIds, users)
	}

	for index, user := range userIds {
		if user != users[index].Id {
			t.Fatalf("Expected user with ID '%s'. Got %#v", user, users[index])
		}
	}
}

func Test_GetUsers_Error_FindUsersWithIdsSuccess(t *testing.T) {
	FindUsersWithIds(t, []string{"0000000000"})
	FindUsersWithIds(t, []string{"0000000001"})
	FindUsersWithIds(t, []string{"0000000000", "0000000001"})
}

func Test_GetUsers_Error_FindUsersByRoleError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersByRoleResponses = []FindUsersByRoleResponse{{[]*User{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users?role=clinic", headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func Test_GetUsers_Error_FindUsersByRoleSuccess(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersByRoleResponses = []FindUsersByRoleResponse{{[]*User{{Id: "0000000000"}, {Id: "1111111111"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/users?role=clinic", headers)
	successResponse := T_ExpectSuccessResponseWithJSONArray(t, response, 200)
	T_ExpectEqualsArray(t, successResponse, []interface{}{map[string]interface{}{"userid": "0000000000", "passwordExists": false}, map[string]interface{}{"userid": "1111111111", "passwordExists": false}})
}

////////////////////////////////////////////////////////////////////////////////

func Test_CreateUser_Error_MissingBody(t *testing.T) {
	response := T_PerformRequest(t, "POST", "/user")
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_MalformedBody(t *testing.T) {
	response := T_PerformRequestBody(t, "POST", "/user", "{")
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_MissingUserDetails(t *testing.T) {
	response := T_PerformRequestBody(t, "POST", "/user", "{}")
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_InvalidUserDetails(t *testing.T) {
	response := T_PerformRequestBody(t, "POST", "/user", "{\"username\": \"a\"}")
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_ErrorFindingUsers(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{nil, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}"
	response := T_PerformRequestBody(t, "POST", "/user", body)
	T_ExpectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateUser_Error_ConflictingEmail(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}"
	response := T_PerformRequestBody(t, "POST", "/user", body)
	T_ExpectErrorResponse(t, response, 409, "Error creating the user")
}

func Test_CreateUser_Error_ErrorUpsertingUser(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{errors.New("ERROR")}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}"
	response := T_PerformRequestBody(t, "POST", "/user", body)
	T_ExpectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateUser_Error_ErrorSettingPermissions(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\", \"roles\": [\"clinic\"]}"
	response := T_PerformRequestBody(t, "POST", "/user", body)
	T_ExpectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateUser_Error_ErrorAddingToken(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableStore.AddTokenResponses = []error{errors.New("ERROR")}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}"
	response := T_PerformRequestBody(t, "POST", "/user", body)
	T_ExpectErrorResponse(t, response, 500, "Error generating the token")
}

func Test_CreateUser_Success(t *testing.T) {
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	responsableStore.AddTokenResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\", \"roles\": [\"clinic\"]}"
	response := T_PerformRequestBody(t, "POST", "/user", body)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 201)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "roles": []interface{}{"clinic"}})
	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatalf("Missing expected %s header", TP_SESSION_TOKEN)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_CreateCustodialUser_Error_MissingSessionToken(t *testing.T) {
	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	response := T_PerformRequestBody(t, "POST", "/user/abcdef1234/user", body)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_CreateCustodialUser_Error_TokenNotFound(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{nil, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/1234567890/user", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_CreateCustodialUser_Error_MismatchUserIds(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/1234567890/user", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_CreateCustodialUser_Error_MissingDetails(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := ""
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateCustodialUser_Error_InvalidDetails(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a\", \"emails\": [\"a\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateCustodialUser_Error_FindUsersError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateCustodialUser_Error_FindUsersDuplicate(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	T_ExpectErrorResponse(t, response, 409, "User already exists")
}

func Test_CreateCustodialUser_Error_UpsertUserError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{errors.New("ERROR")}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateCustodialUser_Error_SetPermissionsError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateCustodialUser_Success_Anonymous(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 201)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{})
}

func Test_CreateCustodialUser_Success_Anonymous_Server(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/0000000000/user", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 201)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"passwordExists": false})
}

func Test_CreateCustodialUser_Success_Known(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 201)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co"})
}

////////////////////////////////////////////////////////////////////////////////
////////// UPDATE USER ////////////////////////////////////////////////////////

func Test_UpdateUser_Error_MissingSessionToken(t *testing.T) {
	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	response := T_PerformRequestBody(t, "PUT", "/user/1111111111", body)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_MissingDetails(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := ""
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_UpdateUser_Error_InvalidDetails(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a\", \"emails\": [\"a\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_UpdateUser_Error_FindUsersError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func Test_UpdateUser_Error_FindUsersMissing(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_PermissionsError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func Test_UpdateUser_Error_NoPermissions(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedRoles_User(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"roles\": [\"clinic\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedRoles_Custodian(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"roles\": [\"clinic\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedEmailVerified_User(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedEmailVerified_Custodian(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedPassword_Custodian(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedTermsAccepted_Custodian(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_FindUserDuplicateError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func Test_UpdateUser_Error_FindUserDuplicateFound(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1234567890"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 409, "User already exists")
}

func Test_UpdateUser_Error_FindUserDuplicateFound2(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1234567890"}, &User{Id: "1234567898"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 409, "User already exists")
}

func Test_UpdateUser_Error_UpsertUserError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{errors.New("ERROR")}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error updating user")
}

func Test_UpdateUser_Error_RemoveCustodians_UsersInGroupError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error updating user")
}

func Test_UpdateUser_Error_RemoveCustodians_SetPermissionsError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	T_ExpectErrorResponse(t, response, 500, "Error updating user")
}

func Test_UpdateUser_Success_Custodian(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co"})
}

func Test_UpdateUser_Success_UserFromUrl(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_UpdateUser_Success_UserWithUnchangedUsername(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111"}}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_UpdateUser_Success_UserFromToken(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_UpdateUser_Success_Server_WithoutPassword(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"roles\": [\"clinic\"], \"emailVerified\": true, \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "roles": []interface{}{"clinic"}, "termsAccepted": "2016-01-01T01:23:45-08:00", "passwordExists": false})
}

func Test_UpdateUser_Success_Server_WithPassword(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"newpassword\", \"roles\": [\"clinic\"], \"emailVerified\": true, \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "roles": []interface{}{"clinic"}, "termsAccepted": "2016-01-01T01:23:45-08:00", "passwordExists": true})
}

////////////////////////////////////////////////////////////////////////////////

func Test_GetUserInfo_Error_MissingSessionToken(t *testing.T) {
	response := T_PerformRequest(t, "GET", "/user/1111111111")
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUserInfo_Error_FindUsersError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func Test_GetUserInfo_Error_FindUsersMissing(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	T_ExpectErrorResponse(t, response, 404, "User not found")
}

func Test_GetUserInfo_Error_FindUsersNil(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{nil}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func Test_GetUserInfo_Error_PermissionsError(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111"}}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	T_ExpectErrorResponse(t, response, 500, "Error finding user")
}

func Test_GetUserInfo_Error_NoPermissions(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111"}}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"a": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	T_ExpectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUserInfo_Success_User(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "1111111111", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_GetUserInfo_Success_Custodian(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_GetUserInfo_Success_Server(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "0000000000", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := T_PerformRequestHeaders(t, "GET", "/user/1111111111", headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00", "passwordExists": true})
}

////////////////////////////////////////////////////////////////////////////////

func TestDeleteUser_StatusForbidden_WhenNoPw(t *testing.T) {
	request, _ := http.NewRequest("DELETE", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request, NO_PARAMS)

	if response.Code != http.StatusForbidden {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusForbidden, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":403,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestDeleteUser_StatusForbidden_WhenEmptyPw(t *testing.T) {

	var jsonData = []byte(`{"password": ""}`)
	request, _ := http.NewRequest("DELETE", "/", bytes.NewBuffer(jsonData))
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request, NO_PARAMS)

	if response.Code != http.StatusForbidden {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusForbidden, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":403,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestDeleteUser_Failure(t *testing.T) {

	var jsonData = []byte(`{"password": "92ggh38"}`)
	req, _ := http.NewRequest("DELETE", "/", bytes.NewBuffer(jsonData))
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	resp := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.DeleteUser(resp, req, NO_PARAMS)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusUnauthorized, resp.Code)
	}
}

func TestDeleteUser_StatusAccepted(t *testing.T) {

	var jsonData = []byte(`{"password": "123youknoWm3"}`)
	request, _ := http.NewRequest("DELETE", "/", bytes.NewBuffer(jsonData))
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request, map[string]string{"userid": USR.Id})

	if response.Code != http.StatusAccepted {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusAccepted, response.Code)
	}
}

func TestDeleteUser_StatusUnauthorized_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("DELETE", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request, NO_PARAMS)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_Login_Error_MissingAuthorization(t *testing.T) {
	response := T_PerformRequest(t, "POST", "/login")
	T_ExpectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_Login_Error_EmptyAuthorization(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "")
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_Login_Error_InvalidAuthorization(t *testing.T) {
	authorization := T_CreateAuthorization(t, "", "")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_Login_Error_FindUsersError(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, http.StatusInternalServerError, STATUS_ERR_FINDING_USR)
}

func Test_Login_Error_FindUsersMissing(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_Login_Error_FindUsersNil(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{nil}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_Login_Error_NoPassword(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111"}}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_Login_Error_PasswordMismatch(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "MISMATCH")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5"}}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_Login_Error_AccountLock(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	nextAttemptTime := time.Now().Add(time.Minute * time.Duration(FAKE_CONFIG.DelayBeforeNextLoginAttempt))
	user := User{
		Id:     "1111111111",
		PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5",
		FailedLogin: &FailedLoginInfos{
			Count:                5,
			Total:                10,
			NextLoginAttemptTime: nextAttemptTime.Format(time.RFC3339),
		},
	}
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&user}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_Login_Error_EmailNotVerified(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 403, "The user hasn't verified this account yet")
}

func Test_Login_Error_ErrorCreatingToken(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", EmailVerified: true}}, nil}}
	responsableStore.AddTokenResponses = []error{errors.New("ERROR")}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	T_ExpectErrorResponse(t, response, 500, "Error updating token")
}

func Test_Login_Success(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", EmailVerified: true}}, nil}}
	responsableStore.AddTokenResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatalf("Missing expected %s header", TP_SESSION_TOKEN)
	}
}

func Test_Login_Success_Password_Complex(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "`-=[]\\;',./~!@#$%^&*)(_+}{|\":<>?`¡™£¢∞§¶•ª–≠‘“æ…÷≥”’")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", PwHash: "80464ae775ca97187d29bc4b3e391e959947138a", EmailVerified: true}}, nil}}
	responsableStore.AddTokenResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login", headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatalf("Missing expected %s header", TP_SESSION_TOKEN)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestServerLogin_StatusBadRequest_WhenNoNameOrSecret(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":400,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestServerLogin_StatusBadRequest_WhenNoName(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":400,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestServerLogin_StatusBadRequest_WhenNoSecret(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":400,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestServerLogin_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("POST", "/serverlogin", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("The session token should have been set")
	}

}

func TestServerLogin_Failure(t *testing.T) {
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set(TP_SERVER_NAME, "shoreline")
	req.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	resp := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.ServerLogin(resp, req)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}
}

func TestServerLogin_StatusUnauthorized_WhenSecretWrong(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, "wrong secret")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":401,"reason":"Wrong password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_PW_WRONG)
	}
}

////////////////////////////////////////////////////////////////////////////////

func (m *MockOAuth) CheckToken(token string) (oauth2.Data, error) {
	d := oauth2.Data{}
	d["userId"] = "1234"
	d["authUserId"] = "4567"
	return d, nil
}

func Test_oauth2Login(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	shoreline.SetHandlers("", rtr)

	//add mock
	mock := &MockOAuth{}
	shoreline.AttachOauth(mock)

	//no header passed
	shoreline.oauth2Login(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, w.Code)
	}

	//with header but no token
	r.Header.Set("Authorization", "bearer")
	w_header := httptest.NewRecorder()
	shoreline.oauth2Login(w_header, r)

	if w_header.Code != http.StatusUnauthorized {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusUnauthorized, w_header.Code)
	}

	//req now sets header
}

func Test_oauth2Login_noheader(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	shoreline.SetHandlers("", rtr)

	//add mock
	mock := &MockOAuth{}
	shoreline.AttachOauth(mock)

	//no header passed
	shoreline.oauth2Login(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, w.Code)
	}

}
func Test_oauth2Login_invalid_header(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	//add mock
	mock := &MockOAuth{}
	shoreline.AttachOauth(mock)
	//with header but no token
	r.Header.Set("Authorization", "bearer")
	w_header := httptest.NewRecorder()
	shoreline.oauth2Login(w_header, r)

	if w_header.Code != http.StatusUnauthorized {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusUnauthorized, w_header.Code)
	}

	//req now sets header
}
func Test_oauth2Login_validheader(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	//add mock
	mock := &MockOAuth{}
	shoreline.AttachOauth(mock)
	//with header but no token
	r.Header.Set("Authorization", "bearer xxx")
	w_header := httptest.NewRecorder()
	shoreline.oauth2Login(w_header, r)

	if w_header.Code != http.StatusOK {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusOK, w_header.Code)
	}

	if w_header.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("Expected the TP_SESSION_TOKEN header to be attached")
	}

	// parse output json
	output := make(map[string]interface{})
	if err := json.Unmarshal(w_header.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	if output["oauthUser"] == nil {
		t.Fatalf("we need to be given a user id but got %v", output)
	}

	if output["oauthTarget"] == nil {
		t.Fatalf("we need to be given a user id but got %v", output)
	}

}

////////////////////////////////////////////////////////////////////////////////

func TestRefreshSession_StatusUnauthorized_WithNoToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.RefreshSession(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusUnauthorized_WithWrongToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, "not this token")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.RefreshSession(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusOK(t *testing.T) {

	shoreline.SetHandlers("", rtr)

	refreshRequest, _ := http.NewRequest("GET", "/", nil)
	refreshRequest.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	response := httptest.NewRecorder()

	shoreline.RefreshSession(response, refreshRequest)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	tokenString := response.Header().Get(TP_SESSION_TOKEN)

	if tokenString == "" {
		t.Fatal("A session token should have been returned")
	}

	if response.Body == nil {
		t.Fatal("A Body should have been returned")
	}

	body, _ := ioutil.ReadAll(response.Body)

	var tokenData TokenData
	_ = json.Unmarshal(body, &tokenData)

	if tokenData.UserId != USR.Id {
		t.Fatalf("should have had a user id of `%v` but was %v", USR.Id, tokenData.UserId)
	}
}

func TestRefreshSession_Failure(t *testing.T) {

	shorelineFails.SetHandlers("", rtr)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	resp := httptest.NewRecorder()

	shorelineFails.RefreshSession(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusUnauthorized, resp.Code)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_LongTermLogin_Error_MissingAuthorization(t *testing.T) {
	response := T_PerformRequest(t, "POST", "/login/thelongtermkey")
	T_ExpectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_LongTermLogin_Error_EmptyAuthorization(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "")
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_LongTermLogin_Error_InvalidAuthorization(t *testing.T) {
	authorization := T_CreateAuthorization(t, "", "")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_LongTermLogin_Error_FindUsersError(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, http.StatusInternalServerError, STATUS_ERR_FINDING_USR)
}

func Test_LongTermLogin_Error_FindUsersMissing(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_LongTermLogin_Error_FindUsersNil(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{nil}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_LongTermLogin_Error_NoPassword(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111"}}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_LongTermLogin_Error_PasswordMismatch(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "MISMATCH")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5"}}, nil}}
	responsableStore.UpsertUserResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_LongTermLogin_Error_EmailNotVerified(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5"}}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 403, "The user hasn't verified this account yet")
}

func Test_LongTermLogin_Error_ErrorCreatingToken(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", EmailVerified: true}}, nil}}
	responsableStore.AddTokenResponses = []error{errors.New("ERROR")}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	T_ExpectErrorResponse(t, response, 500, "Error updating token")
}

func Test_LongTermLogin_Success(t *testing.T) {
	authorization := T_CreateAuthorization(t, "a@b.co", "password")
	responsableStore.FindUsersResponses = []FindUsersResponse{{[]*User{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", EmailVerified: true}}, nil}}
	responsableStore.AddTokenResponses = []error{nil}
	defer T_ExpectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := T_PerformRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	successResponse := T_ExpectSuccessResponseWithJSONMap(t, response, 200)
	T_ExpectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	T_ExpectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatalf("Missing expected %s header", TP_SESSION_TOKEN)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestHasServerToken_True(t *testing.T) {

	shoreline.SetHandlers("", rtr)

	//login as server
	svrLoginRequest, _ := http.NewRequest("POST", "/", nil)
	svrLoginRequest.Header.Set(TP_SERVER_NAME, "shoreline")
	svrLoginRequest.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.ServerLogin(response, svrLoginRequest)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("The session token should have been set")
	}

	if hasServerToken(response.Header().Get(TP_SESSION_TOKEN), shoreline.ApiConfig.Secret) == false {
		t.Fatal("The token should have been a valid server token")
	}
}

func TestServerCheckToken_StatusOK(t *testing.T) {

	//the api

	shoreline.SetHandlers("", rtr)

	//step 1 - login as server
	request, _ := http.NewRequest("POST", "/serverlogin", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back from login")
	}

	//step 2 - do the check
	checkTokenRequest, _ := http.NewRequest("GET", "/", nil)
	checkTokenRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)
	checkTokenResponse := httptest.NewRecorder()

	shoreline.ServerCheckToken(checkTokenResponse, checkTokenRequest, map[string]string{"token": svrTokenToUse})

	if checkTokenResponse.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, checkTokenResponse.Code)
	}

	if checkTokenResponse.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
	}

	body, _ := ioutil.ReadAll(checkTokenResponse.Body)

	var tokenData TokenData
	_ = json.Unmarshal(body, &tokenData)

	t.Log("token data returned ", tokenData)

	if tokenData.UserId != "shoreline" {
		t.Fatalf("should have had a server id of `shoreline` but was %v", tokenData.UserId)
	}

	if tokenData.IsServer != true {
		t.Fatalf("should have been a server token but was %v", tokenData.IsServer)
	}
}

func TestServerCheckToken_StatusUnauthorized_WhenNoSvrToken(t *testing.T) {

	//the api

	shoreline.SetHandlers("", rtr)

	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	shoreline.ServerCheckToken(response, request, NO_PARAMS)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestLogout_StatusOK_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.Logout(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}
}

func TestLogout_StatusOK(t *testing.T) {

	shoreline.SetHandlers("", rtr)
	//now logout with valid token
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	response := httptest.NewRecorder()

	shoreline.Logout(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}
}

func TestLogout_Failure(t *testing.T) {

	shorelineFails.SetHandlers("", rtr)
	//now logout with valid token
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.ID)
	resp := httptest.NewRecorder()

	shorelineFails.Logout(resp, req)

	//StatusOK beccuse we `try` and delete the token but the return of that
	if resp.Code != http.StatusOK {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusOK, resp.Code)
	}
}

func TestAnonymousIdHashPair_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)

	values := request.URL.Query()
	values.Add("one", "somestuff")
	values.Add("two", "some more stuff")
	request.URL.RawQuery = values.Encode()

	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.AnonymousIdHashPair(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
	}

	body, _ := ioutil.ReadAll(response.Body)

	var anonIdHashPair AnonIdHashPair
	_ = json.Unmarshal(body, &anonIdHashPair)

	if anonIdHashPair.Name != "" {
		t.Fatalf("should have no name but was %v", anonIdHashPair.Name)
	}
	if anonIdHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", anonIdHashPair.Id)
	}
	if anonIdHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", anonIdHashPair.Hash)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestAnonymousIdHashPair_StatusOK_EvenWhenNoURLParams(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)

	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.AnonymousIdHashPair(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
	}

	body, _ := ioutil.ReadAll(response.Body)

	var anonIdHashPair AnonIdHashPair
	_ = json.Unmarshal(body, &anonIdHashPair)

	if anonIdHashPair.Name != "" {
		t.Fatalf("should have no name but was %v", anonIdHashPair.Name)
	}
	if anonIdHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", anonIdHashPair.Id)
	}
	if anonIdHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", anonIdHashPair.Hash)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestAnonIdHashPair_InBulk(t *testing.T) {

	shoreline.SetHandlers("", rtr)

	// we ask for 100 AnonymousIdHashPair to be created
	//NOTE: while we can run more loaccly travis dosen't like it so 100 should be good enough
	ask := make([]AnonIdHashPair, 100)
	var generated []AnonIdHashPair

	var mutex sync.Mutex
	var wg sync.WaitGroup

	for _, hash := range ask {
		wg.Add(1)
		go func(hash AnonIdHashPair) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "/", nil)
			res := httptest.NewRecorder()
			shoreline.AnonymousIdHashPair(res, req)
			body, _ := ioutil.ReadAll(res.Body)
			json.Unmarshal(body, &hash)
			mutex.Lock()
			generated = append(generated, hash)
			mutex.Unlock()
		}(hash)

	}
	wg.Wait()

	// need a more elogent way for this
	id1 := generated[1].Id
	matches1 := 0

	id33 := generated[33].Id
	matches33 := 0

	for i := range generated {
		if id1 == generated[i].Id {
			matches1++
		}
		if id33 == generated[i].Id {
			matches33++
		}
	}

	if matches1 > 1 || matches33 > 1 {
		t.Log("id: ", id1, "has ", matches1, "matches")
		t.Log("id: ", id33, "has ", matches33, "matches")
		t.Fatal("Hashed Ids should be unique")
	}

}

////////////////////////////////////////////////////////////////////////////////

func Test_AuthenticateSessionToken_Missing(t *testing.T) {
	tokenData, err := responsableShoreline.authenticateSessionToken("")
	if err == nil {
		t.Fatalf("Unexpected success")
	}
	if err.Error() != "Session token is empty" {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if tokenData != nil {
		t.Fatalf("Unexpected token data returned: %#v", tokenData)
	}
}

func Test_AuthenticateSessionToken_Invalid(t *testing.T) {
	tokenData, err := responsableShoreline.authenticateSessionToken("xyz")
	if err == nil {
		t.Fatalf("Unexpected success")
	}
	if err.Error() != "token contains an invalid number of segments" {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if tokenData != nil {
		t.Fatalf("Unexpected token data returned: %#v", tokenData)
	}
}

func Test_AuthenticateSessionToken_Expired(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, -3600)
	tokenData, err := responsableShoreline.authenticateSessionToken(sessionToken.ID)
	if err == nil {
		t.Fatalf("Unexpected success")
	}
	if err.Error() != "Token is expired" {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if tokenData != nil {
		t.Fatalf("Unexpected token data returned: %#v", tokenData)
	}
}

func Test_AuthenticateSessionToken_NotFound(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{nil, errors.New("NOT FOUND")}}
	defer T_ExpectResponsablesEmpty(t)

	tokenData, err := responsableShoreline.authenticateSessionToken(sessionToken.ID)
	if err == nil {
		t.Fatalf("Unexpected success")
	}
	if err.Error() != "NOT FOUND" {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if tokenData != nil {
		t.Fatalf("Unexpected token data returned: %#v", tokenData)
	}
}

func Test_AuthenticateSessionToken_Success_User(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", false, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	tokenData, err := responsableShoreline.authenticateSessionToken(sessionToken.ID)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if tokenData == nil {
		t.Fatalf("Missing expected token data")
	}
	if tokenData.UserId != "abcdef1234" {
		t.Fatalf("Unexpected token user id: %s", tokenData.UserId)
	}
	if tokenData.IsServer {
		t.Fatalf("Unexpected server token")
	}
	if tokenData.DurationSecs != TOKEN_DURATION {
		t.Fatalf("Unexpected token duration: %v", tokenData.DurationSecs)
	}
}

func Test_AuthenticateSessionToken_Success_Server(t *testing.T) {
	sessionToken := T_CreateSessionToken(t, "abcdef1234", true, TOKEN_DURATION)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer T_ExpectResponsablesEmpty(t)

	tokenData, err := responsableShoreline.authenticateSessionToken(sessionToken.ID)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if tokenData == nil {
		t.Fatalf("Missing expected token data")
	}
	if tokenData.UserId != "abcdef1234" {
		t.Fatalf("Unexpected token user id: %s", tokenData.UserId)
	}
	if !tokenData.IsServer {
		t.Fatalf("Unexpected non-server token")
	}
	if tokenData.DurationSecs != TOKEN_DURATION {
		t.Fatalf("Unexpected token duration: %v", tokenData.DurationSecs)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_TokenUserHasRequestedPermissions_Server(t *testing.T) {
	tokenData := &TokenData{UserId: "abcdef1234", IsServer: true, DurationSecs: TOKEN_DURATION}
	requestedPermissions := clients.Permissions{"a": clients.Allowed, "b": clients.Allowed}
	permissions, err := responsableShoreline.tokenUserHasRequestedPermissions(tokenData, "1234567890", requestedPermissions)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if !reflect.DeepEqual(permissions, requestedPermissions) {
		t.Fatalf("Unexpected permissions returned: %#v", permissions)
	}
}

func Test_TokenUserHasRequestedPermissions_Owner(t *testing.T) {
	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: TOKEN_DURATION}
	requestedPermissions := clients.Permissions{"a": clients.Allowed, "b": clients.Allowed}
	permissions, err := responsableShoreline.tokenUserHasRequestedPermissions(tokenData, "abcdef1234", requestedPermissions)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if !reflect.DeepEqual(permissions, requestedPermissions) {
		t.Fatalf("Unexpected permissions returned: %#v", permissions)
	}
}

func Test_TokenUserHasRequestedPermissions_GatekeeperError(t *testing.T) {
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: TOKEN_DURATION}
	requestedPermissions := clients.Permissions{"a": clients.Allowed, "b": clients.Allowed}
	permissions, err := responsableShoreline.tokenUserHasRequestedPermissions(tokenData, "1234567890", requestedPermissions)
	if err == nil {
		t.Fatalf("Unexpected success")
	}
	if err.Error() != "ERROR" {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if len(permissions) != 0 {
		t.Fatalf("Unexpected permissions returned: %#v", permissions)
	}
}

func Test_TokenUserHasRequestedPermissions_CompleteMismatch(t *testing.T) {
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"y": clients.Allowed, "z": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: TOKEN_DURATION}
	requestedPermissions := clients.Permissions{"a": clients.Allowed, "b": clients.Allowed}
	permissions, err := responsableShoreline.tokenUserHasRequestedPermissions(tokenData, "1234567890", requestedPermissions)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if len(permissions) != 0 {
		t.Fatalf("Unexpected permissions returned: %#v", permissions)
	}
}

func Test_TokenUserHasRequestedPermissions_PartialMismatch(t *testing.T) {
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"a": clients.Allowed, "z": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: TOKEN_DURATION}
	requestedPermissions := clients.Permissions{"a": clients.Allowed, "b": clients.Allowed}
	permissions, err := responsableShoreline.tokenUserHasRequestedPermissions(tokenData, "1234567890", requestedPermissions)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if !reflect.DeepEqual(permissions, clients.Permissions{"a": clients.Allowed}) {
		t.Fatalf("Unexpected permissions returned: %#v", permissions)
	}
}

func Test_TokenUserHasRequestedPermissions_FullMatch(t *testing.T) {
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"a": clients.Allowed, "b": clients.Allowed}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: TOKEN_DURATION}
	requestedPermissions := clients.Permissions{"a": clients.Allowed, "b": clients.Allowed}
	permissions, err := responsableShoreline.tokenUserHasRequestedPermissions(tokenData, "1234567890", requestedPermissions)
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
	if !reflect.DeepEqual(permissions, requestedPermissions) {
		t.Fatalf("Unexpected permissions returned: %#v", permissions)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_RemoveUserPermissions_Error_UsersInGroupError(t *testing.T) {
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	err := responsableShoreline.removeUserPermissions("1", clients.Permissions{"a": clients.Allowed})
	if err == nil {
		t.Fatalf("Unexpected success")
	}
	if err.Error() != "ERROR" {
		t.Fatalf("Unexpected error: %#v", err)
	}
}

func Test_RemoveUserPermissions_Error_SetPermissionsError(t *testing.T) {
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"1": {"root": clients.Allowed}, "2": {"a": clients.Allowed, "b": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer T_ExpectResponsablesEmpty(t)

	err := responsableShoreline.removeUserPermissions("1", clients.Permissions{"a": clients.Allowed})
	if err == nil {
		t.Fatalf("Unexpected success")
	}
	if err.Error() != "ERROR" {
		t.Fatalf("Unexpected error: %#v", err)
	}
}

func Test_RemoveUserPermissions_Success(t *testing.T) {
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"1": {"root": clients.Allowed}, "2": {"a": clients.Allowed, "b": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer T_ExpectResponsablesEmpty(t)

	err := responsableShoreline.removeUserPermissions("1", clients.Permissions{"a": clients.Allowed})
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
}
