package user

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/shoreline/keycloak"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	clinicClient "github.com/tidepool-org/clinic/client"
)

const (
	theSecret  = "shhh! don't tell"
	makeItFail = true
)

func InitAPITest(cfg ApiConfig, logger *log.Logger, store Storage, keycloakClient keycloak.Client, userEventsNotifier EventsNotifier, seagull clients.Seagull, clinic clinicClient.ClientWithResponsesInterface) *Api {
	return &Api{
		Store:              store,
		ApiConfig:          cfg,
		logger:             logger,
		keycloakClient:     keycloakClient,
		userEventsNotifier: userEventsNotifier,
		seagull:            seagull,
		tokenAuthenticator: NewTokenAuthenticator(keycloakClient, store, cfg.TokenConfigs),
		clinic:             clinic,
	}
}

var (
	noParams      = map[string]string{}
	tokenDuration = int64(3600)
	fakeConfig    = ApiConfig{
		ServerSecret: "shhh! don't tell",
		TokenConfigs: []TokenConfig{{
			EncodeKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzg3MHpXfMuH4AJ4URtaG4QvZenpfuSz2FmIwdnPEtkrKFmL2
6b89U1tw5WsYAE158znAzPptDA25hAsIcTAqULNsoY3WV2zmsLrUX8pUaCTfExXN
dMFDruR676G3pJWcsI1GuePK5/v3dBHjjTYdtVJiogbCtP+XYT/k1qHZztwRY4oH
Ma8LorxUZco0Mf6qOq5tmRUJhxvCESaqUTpTAIIfByMnPmnIHOHnsYtkiZQBms2x
o1UfpYnqZX2CoN+wPoMoSAlRbnOmmHYbbMFVPNTj7NINwVb8K8iDU7lFR+JfN3UG
lErVo7XCDQcbwTpiZbdj9zWSWbYtIBNBqkNxxwIDAQABAoIBAG3IMhmVlh6BAGYr
0vfO8nvSmWNE8d0yFEbmt5VUptjMzhDRV2ZAascPr/27akU3AiNRgOR1BEZoxY+R
ZUUQ+WqXvefxLuLTdbFxSRdkMEZwZp2/fwCWu53hw5IK4lIBGEOEccs2j3O77iJc
KZWh4IArzbsvyOswRhIdPaoQ/3/TECPa5AXY7LAEj32XfP3K08rRAldgdfTv6XbV
e/pzKMzqgPMIhZ3mG1n7CJ+DLhajEEG36KwszI6OttkjzyBzlsQb3rskEOypG3ZU
k24B++v3Cm7FN0vG+FLFVzwS5rDrF+CUIFCyQU/nAB8nmkiNdCbDI0/614NeSSnE
BZc6G1ECgYEA/zVJdpRx5kgFDyxmJrdVcXJ/digGDct6og0pffcJW1ygBnt+tLRd
gpH+oBNUMz92GKb+wTTlOba0CNbJULM1sZklf604yzpIDji0HyI2oZ0fo+OEkpBz
PyNrdnm2WXF4e3WCb1ehkxGMyfTH70RFKqmPRMka1xWAMXPgbP5Osj8CgYEAzrF3
iAX+geyqagzQfbt5bf9zePmL4Dx6J37pgtZSo88sqtSU6+eYQsF/pS5KrtxD6Sql
5qSbfKekmDhEF4DMUeva76JHmPIPdJH+fPyw6jOB6S3tS+i41S2CGNub1RLz7LCj
NEZ9H5GBVmxBTdiZL3aZWgIxo63Nl0H39k6+TnkCgYEA44Nkx5LU659+6yUAuDku
seGKIhLSOtAQtpEXUVW/ALTVcJH9xikZSALRRXGV2c4UgSu25xU52Ta4zzxz4j6x
em92D5mkjQCbJhqE8VB19aP2hguZr3OZWktATTF6T8ipyR5cNtifkVXO9mgDKZnq
M3tP3tmN1Ps0+mE8TM51588CgYBZYgtz6kuued8UL2h2Bv2zINYZyajAlsaoj8yB
hReFuVDyqy2feq6wp6cAkq0/QwenLIdD34lR9dlK7oIbu9ofzyQFnyLhNESUv5HT
ER+cmBuk7/R/cCuGHMD26PlRwnlzsMtTDuyLG0xYSEZRWMqd6ObWMr6urrmKoL+P
Z2wK2QKBgQC7SZ47YM45pz23yjyrKx6dUAfw5imb6ylZPft24A+W2tFanfRDQITX
wGHgJHaV+gd52zrP6s8AKzMjMcRtB0g0CGf5Qe1BHMh89fJsUKToT8L+040kWl/P
upYmRYNT7J2Met0WVB6u6ZDFSMl+CIFLXHGtU47DjGUmQxqmhW8LOg==
-----END RSA PRIVATE KEY-----`,
			DecodeKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzg3MHpXfMuH4AJ4URtaG
4QvZenpfuSz2FmIwdnPEtkrKFmL26b89U1tw5WsYAE158znAzPptDA25hAsIcTAq
ULNsoY3WV2zmsLrUX8pUaCTfExXNdMFDruR676G3pJWcsI1GuePK5/v3dBHjjTYd
tVJiogbCtP+XYT/k1qHZztwRY4oHMa8LorxUZco0Mf6qOq5tmRUJhxvCESaqUTpT
AIIfByMnPmnIHOHnsYtkiZQBms2xo1UfpYnqZX2CoN+wPoMoSAlRbnOmmHYbbMFV
PNTj7NINwVb8K8iDU7lFR+JfN3UGlErVo7XCDQcbwTpiZbdj9zWSWbYtIBNBqkNx
xwIDAQAB
-----END PUBLIC KEY-----`,
			DurationSecs: tokenDuration,
			Audience:     "localhost",
			Issuer:       "localhost",
			Algorithm:    "RS256",
		}},

		LongTermKey:        "thelongtermkey",
		Salt:               "a mineral substance composed primarily of sodium chloride",
		VerificationSecret: "",
		ClinicDemoUserID:   "00000000",
	}
	/*
	 * users and tokens
	 */
	user           = &User{Id: "123-99-100", Username: "test@new.bar", Emails: []string{"test@new.bar"}}
	userToken, _   = CreateSessionToken(&TokenData{UserId: user.Id, IsServer: false, DurationSecs: tokenDuration}, fakeConfig.TokenConfigs[0])
	serverToken, _ = CreateSessionToken(&TokenData{UserId: "shoreline", IsServer: true, DurationSecs: tokenDuration}, fakeConfig.TokenConfigs[0])

	mockClinic = &clinicClient.MockClientWithResponsesInterface{}

	/*
	 * basics setup
	 */
	rtr = mux.NewRouter()
	/*
	 * expected path
	 */
	logger             = log.New(os.Stdout, USER_API_PREFIX, log.LstdFlags|log.Lshortfile)
	mockNotifier       = &MockEventsNotifier{}
	mockStore          = NewMockStoreClient(fakeConfig.Salt, false, false)
	mockKeycloakClient = &keycloak.MockClient{}
	mockSeagull        = clients.NewSeagullMock()
	shoreline          = InitAPITest(fakeConfig, logger, mockStore, mockKeycloakClient, mockNotifier, mockSeagull, mockClinic)

	/*
	 * failure path
	 */
	mockStoreFails = NewMockStoreClient(fakeConfig.Salt, false, makeItFail)
	shorelineFails = InitAPITest(fakeConfig, logger, mockStoreFails, mockKeycloakClient, mockNotifier, mockSeagull, mockClinic)

	responsableStore      = NewResponsableMockStoreClient()
	responsableGatekeeper = NewResponsableMockGatekeeper()
	responsableShoreline  = InitShoreline(fakeConfig, responsableStore, responsableGatekeeper, mockNotifier)
)

func InitShoreline(config ApiConfig, store Storage, perms clients.Gatekeeper, notifier EventsNotifier) *Api {
	api := InitAPITest(config, logger, store, mockKeycloakClient, notifier, mockSeagull, mockClinic)
	api.AttachPerms(perms)
	return api
}

////////////////////////////////////////////////////////////////////////////////

func createAuthorization(t *testing.T, email string, password string) string {
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", email, password))))
}

func createSessionToken(t *testing.T, userID string, isServer bool, duration int64) *SessionToken {
	sessionToken, err := CreateSessionToken(&TokenData{UserId: userID, IsServer: isServer, DurationSecs: duration}, fakeConfig.TokenConfigs[0])
	if err != nil {
		t.Fatalf("Error creating session token: %#v", err)
	}
	return sessionToken
}

func performRequest(t *testing.T, method string, url string) *httptest.ResponseRecorder {
	return performRequestBodyHeaders(t, method, url, "", nil)
}

func performRequestBody(t *testing.T, method string, url string, body string) *httptest.ResponseRecorder {
	return performRequestBodyHeaders(t, method, url, body, nil)
}

func performRequestHeaders(t *testing.T, method string, url string, headers http.Header) *httptest.ResponseRecorder {
	return performRequestBodyHeaders(t, method, url, "", headers)
}

func performRequestBodyHeaders(t *testing.T, method string, url string, body string, headers http.Header) *httptest.ResponseRecorder {
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

func expectErrorResponse(t *testing.T, response *httptest.ResponseRecorder, expectedCode int, expectedReason string) {
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

func expectSuccessResponse(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) string {
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

func expectSuccessResponseWithJSON(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) {
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

func expectSuccessResponseWithJSONArray(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) []interface{} {
	expectSuccessResponseWithJSON(t, response, expectedCode)

	var successResponse []interface{}
	if err := json.NewDecoder(response.Body).Decode(&successResponse); err != nil {
		t.Fatalf("Error parsing response body: %#v", err)
	}
	return successResponse
}

func expectSuccessResponseWithJSONMap(t *testing.T, response *httptest.ResponseRecorder, expectedCode int) map[string]interface{} {
	expectSuccessResponseWithJSON(t, response, expectedCode)

	var successResponse map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&successResponse); err != nil {
		t.Fatalf("Error parsing response body: %#v", err)
	}
	return successResponse
}

func expectElementMatch(t *testing.T, actual map[string]interface{}, key string, pattern string, remove bool) {
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

func expectEqualsArray(t *testing.T, actual []interface{}, expected []interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Actual %#v does not match expected %#v", actual, expected)
	}
}

func expectEqualsMap(t *testing.T, actual map[string]interface{}, expected map[string]interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Actual %#v does not match expected %#v", actual, expected)
	}
}

func expectResponsablesEmpty(t *testing.T) {
	if responsableStore.HasResponses() {
		if len(responsableStore.PingResponses) > 0 {
			t.Logf("PingResponses still available")
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
		if len(responsableStore.RemoveTokensForUserResponses) > 0 {
			t.Logf("RemoveTokensForUserResponses still available")
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
	if mockNotifier.HasResponses() {
		if len(mockNotifier.NotifyUserDeletedResponses) > 0 {
			t.Logf("NotifyUserDeletedResponses still available")
		}
		if len(mockNotifier.NotifyUserCreatedResponses) > 0 {
			t.Logf("NotifyUserCreatedResponses still available")
		}
		if len(mockNotifier.NotifyUserUpdatedResponses) > 0 {
			t.Logf("NotifyUserUpdatedResponses still available")
		}
		mockNotifier.Reset()
		t.Fail()
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestGetStatus_StatusOk(t *testing.T) {

	request, _ := http.NewRequest("GET", "/status", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.GetStatus(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Resp given [%d] expected [%d] ", response.Code, http.StatusOK)
	}

}

func TestGetStatus_StatusInternalServerError(t *testing.T) {

	request, _ := http.NewRequest("GET", "/status", nil)
	response := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.GetStatus(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("Resp given [%d] expected [%d] ", response.Code, http.StatusInternalServerError)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != "Session failure" {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), "Session failure")
	}

}

func TestGetMetrics_StatusCount(t *testing.T) {

	performRequest(t, "GET", "/users?role=clinic")

	response := performRequest(t, "GET", "/metrics")

	if response.Code != http.StatusOK {
		t.Fatalf("Resp given [%d] expected [%d] ", response.Code, http.StatusOK)
	}
	if p, err := ioutil.ReadAll(response.Body); err != nil {
		t.Fail()
	} else {
		metric := fmt.Sprintf("tidepool_shoreline_failed_status_count{status_code=\"%d\",status_reason=\"%s\"}", 401, STATUS_UNAUTHORIZED)
		if !strings.Contains(string(p), metric) {
			t.Errorf("Expected %s in response: \n%s", metric, p)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_GetUsers_Error_MissingSessionToken(t *testing.T) {
	response := performRequest(t, "GET", "/users?role=clinic")
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUsers_Error_TokenError(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users?role=clinic", headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUsers_Error_NotServerToken(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users?role=clinic", headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUsers_Error_InvalidRole(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users?role=invalid", headers)
	expectErrorResponse(t, response, 400, "The role specified is invalid")
}

func Test_GetUsers_Error_NoQuery(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users", headers)
	expectErrorResponse(t, response, 400, "A query must be specified")
}

func Test_GetUsers_Error_InvalidQuery(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users?yolo=swag", headers)
	expectErrorResponse(t, response, 400, "Unknown query parameter")
}

func Test_GetUsers_Error_FindUsersWithIdsError(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersWithIdsResponses = []FindUsersWithIdsResponse{{[]*User{}, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users?id=abcdef1234", headers)
	expectErrorResponse(t, response, 500, "Error finding user")
}

func FindUsersWithIds(t *testing.T, userIds []string) {
	rr := httptest.NewRecorder()

	r, err := http.NewRequest("GET", "/users?id="+strings.Join(userIds, ","), nil)
	r.Header.Set(TP_SESSION_TOKEN, serverToken.ID)
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
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersByRoleResponses = []FindUsersByRoleResponse{{[]*User{}, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users?role=clinic", headers)
	expectErrorResponse(t, response, 500, "Error finding user")
}

func Test_GetUsers_Error_FindUsersByRoleSuccess(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersByRoleResponses = []FindUsersByRoleResponse{{[]*User{{Id: "0000000000"}, {Id: "1111111111"}}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/users?role=clinic", headers)
	successResponse := expectSuccessResponseWithJSONArray(t, response, 200)
	expectEqualsArray(t, successResponse, []interface{}{map[string]interface{}{"userid": "0000000000", "passwordExists": false}, map[string]interface{}{"userid": "1111111111", "passwordExists": false}})
}

func Test_GetUsers_FindUsersByRoleAndDateSuccess(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUsersByRoleAndDateResponses = []FindUsersByRoleAndDateResponse{{[]*User{{Id: "0000000000"}, {Id: "1111111111"}}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)

	createdFromQuery := time.Now().Add(time.Hour * -5).Format("2006-01-02")
	createdToQuery := time.Now().Format("2006-01-02")
	response := performRequestHeaders(t, "GET", "/users?role=clinic&createdFrom="+createdFromQuery+"&createdTo="+createdToQuery, headers)
	successResponse := expectSuccessResponseWithJSONArray(t, response, 200)
	expectEqualsArray(t, successResponse, []interface{}{map[string]interface{}{"userid": "0000000000", "passwordExists": false}, map[string]interface{}{"userid": "1111111111", "passwordExists": false}})
}

////////////////////////////////////////////////////////////////////////////////

func Test_CreateUser_Error_MissingBody(t *testing.T) {
	response := performRequest(t, "POST", "/user")
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_MalformedBody(t *testing.T) {
	response := performRequestBody(t, "POST", "/user", "{")
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_MissingUserDetails(t *testing.T) {
	response := performRequestBody(t, "POST", "/user", "{}")
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_InvalidUserDetails(t *testing.T) {
	response := performRequestBody(t, "POST", "/user", "{\"username\": \"a\"}")
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateUser_Error_ErrorFindingUsers(t *testing.T) {
	responsableStore.FindUserResponses = []FindUserResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}"
	response := performRequestBody(t, "POST", "/user", body)
	expectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateUser_Error_ConflictingEmail(t *testing.T) {
	responsableStore.FindUserResponses = []FindUserResponse{{&User{}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}"
	response := performRequestBody(t, "POST", "/user", body)
	expectErrorResponse(t, response, 409, "User already exists")
}

func Test_CreateUser_Error_ErrorCreatingUser(t *testing.T) {
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}"
	response := performRequestBody(t, "POST", "/user", body)
	expectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateUser_Error_ErrorSettingPermissions(t *testing.T) {
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{&User{Id: "1234567890", Roles: []string{"clinic"}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\", \"roles\": [\"clinic\"]}"
	response := performRequestBody(t, "POST", "/user", body)
	expectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateUser_Success(t *testing.T) {
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{&User{Id: "1234567890", Emails: []string{"a@z.co"}, Username: "a@z.co", Roles: []string{"clinic"}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer expectResponsablesEmpty(t)

	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	token := &oauth2.Token{AccessToken: "access_token", RefreshToken: "refresh_token"}
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@z.co", "password").Return(token, nil)
	defer mockCtrl.Finish()

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"password\", \"roles\": [\"clinic\"]}"
	response := performRequestBody(t, "POST", "/user", body)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 201)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "roles": []interface{}{"clinic"}})
	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatalf("Missing expected %s header", TP_SESSION_TOKEN)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_CreateCustodialUser_Error_MissingSessionToken(t *testing.T) {
	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	response := performRequestBody(t, "POST", "/user/abcdef1234/user", body)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_CreateCustodialUser_Error_TokenNotFound(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{nil, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/1234567890/user", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_CreateCustodialUser_Error_MismatchUserIds(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/1234567890/user", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_CreateCustodialUser_Error_MissingDetails(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	body := ""
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateCustodialUser_Error_InvalidDetails(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a\", \"emails\": [\"a\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_CreateCustodialUser_Error_FindUsersError(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	expectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateCustodialUser_Error_FindUsersDuplicate(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1234"}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	expectErrorResponse(t, response, 409, "User already exists")
}

func Test_CreateCustodialUser_Error_CreateUserError(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	expectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateCustodialUser_Error_SetPermissionsError(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{&User{}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	expectErrorResponse(t, response, 500, "Error creating the user")
}

func Test_CreateCustodialUser_Success_Anonymous(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{&User{Id: "1234567890"}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 201)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{})
}

func Test_CreateCustodialUser_Success_Anonymous_Server(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{&User{Id: "1234567890"}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/0000000000/user", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 201)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"passwordExists": false})
}

func Test_CreateCustodialUser_Success_Known(t *testing.T) {
	sessionToken := createSessionToken(t, "abcdef1234", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{&User{Id: "1234567890", Username: "a@z.co", Emails: []string{"a@z.co"}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/user/abcdef1234/user", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 201)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co"})
}

func Test_CreateClinicCustodialUser_Success_Known(t *testing.T) {
	sessionToken := createSessionToken(t, "clinic", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	responsableStore.CreateUserResponses = []CreateUserResponse{{&User{Id: "1234567890", Username: "a@z.co", Emails: []string{"a@z.co"}}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "POST", "/v1/clinics/12345/users", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 201)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "passwordExists": false, "username": "a@z.co"})
}

////////////////////////////////////////////////////////////////////////////////

func Test_UpdateUser_Error_MissingSessionToken(t *testing.T) {
	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	response := performRequestBody(t, "PUT", "/user/1111111111", body)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_MissingDetails(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	body := ""
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_UpdateUser_Error_InvalidDetails(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a\", \"emails\": [\"a\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 400, "Invalid user details were given")
}

func Test_UpdateUser_Error_FindUsersError(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 500, "Error finding user")
}

func Test_UpdateUser_Error_FindUsersMissing(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_PermissionsError(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 500, "Error finding user")
}

func Test_UpdateUser_Error_NoPermissions(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true, \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedRoles_User(t *testing.T) {
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"roles\": [\"clinic\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedRoles_Custodian(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"roles\": [\"clinic\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedEmailVerified_User(t *testing.T) {
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedEmailVerified_Custodian(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"emailVerified\": true}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedPassword_Custodian(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_UnauthorizedTermsAccepted_Custodian(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_DuplicateError(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{nil, ErrEmailConflict}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 409, "User already exists")
}

func Test_UpdateUser_Error_UpdateUserError(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 500, "Error updating user")
}

func Test_UpdateUser_Error_UpdateUserBrokeredError(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Roles: []string{RoleBrokered}}, nil}}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, http.StatusUnauthorized, "Not authorized for requested operation")
}

func Test_UpdateUser_Error_RemoveCustodians_UsersInGroupError(t *testing.T) {
	updatedUser := &User{
		Id:            "1111111111",
		Username:      "a@z.co",
		Emails:        []string{"a@z.co"},
		PwHash:        "newpasswordhash",
		EmailVerified: false,
		Enabled:       true,
	}
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{updatedUser, nil}}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{}, errors.New("ERROR")}}
	mockNotifier.NotifyUserUpdatedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	mockCtrl := gomock.NewController(t)
	mockClinic.Reset(mockCtrl)
	mockClinic.EXPECT().ListClinicsForPatientWithResponse(gomock.Any(), gomock.Eq(clinicClient.UserId("1111111111")), gomock.Any()).Return(&clinicClient.ListClinicsForPatientResponse{
		JSON200: &clinicClient.PatientClinicRelationships{},
		HTTPResponse: &http.Response{
			StatusCode: http.StatusOK,
		},
	}, nil)
	defer mockCtrl.Finish()

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 500, "Error updating user")
}

func Test_UpdateUser_Error_RemoveCustodians_SetPermissionsError(t *testing.T) {
	updatedUser := &User{
		Id:            "1111111111",
		Username:      "a@z.co",
		Emails:        []string{"a@z.co"},
		PwHash:        "newpasswordhash",
		EmailVerified: false,
		Enabled:       true,
	}
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{updatedUser, nil}}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	mockNotifier.NotifyUserUpdatedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	mockCtrl := gomock.NewController(t)
	mockClinic.Reset(mockCtrl)
	mockClinic.EXPECT().ListClinicsForPatientWithResponse(gomock.Any(), gomock.Eq(clinicClient.UserId("1111111111")), gomock.Any()).Return(&clinicClient.ListClinicsForPatientResponse{
		JSON200: &clinicClient.PatientClinicRelationships{},
		HTTPResponse: &http.Response{
			StatusCode: http.StatusOK,
		},
	}, nil)
	defer mockCtrl.Finish()

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"12345678\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	expectErrorResponse(t, response, 500, "Error updating user")
}

func Test_UpdateUser_Success_Custodian(t *testing.T) {
	updatedUser := &User{
		Id:            "1111111111",
		Username:      "a@z.co",
		Emails:        []string{"a@z.co"},
		EmailVerified: false,
		Enabled:       true,
	}
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{updatedUser, nil}}
	mockNotifier.NotifyUserUpdatedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"]}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co"})
}

func Test_UpdateUser_Success_UserFromUrl(t *testing.T) {
	updatedUser := &User{
		Id:            "1111111111",
		Username:      "a@z.co",
		Emails:        []string{"a@z.co"},
		TermsAccepted: "2016-01-01T01:23:45-08:00",
		PwHash:        "newpasswordhash",
		EmailVerified: false,
		Enabled:       true,
	}
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{updatedUser, nil}}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	mockNotifier.NotifyUserUpdatedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	mockCtrl := gomock.NewController(t)
	mockClinic.Reset(mockCtrl)
	mockClinic.EXPECT().ListClinicsForPatientWithResponse(gomock.Any(), gomock.Eq(clinicClient.UserId("1111111111")), gomock.Any()).Return(&clinicClient.ListClinicsForPatientResponse{
		JSON200: &clinicClient.PatientClinicRelationships{},
		HTTPResponse: &http.Response{
			StatusCode: http.StatusOK,
		},
	}, nil)
	defer mockCtrl.Finish()

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_UpdateUser_Success_UserFromToken(t *testing.T) {
	updatedUser := &User{
		Id:            "1111111111",
		Username:      "a@z.co",
		Emails:        []string{"a@z.co"},
		TermsAccepted: "2016-01-01T01:23:45-08:00",
		PwHash:        "newpasswordhash",
		EmailVerified: false,
		Enabled:       true,
	}
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{updatedUser, nil}}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	mockNotifier.NotifyUserUpdatedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	mockCtrl := gomock.NewController(t)
	mockClinic.Reset(mockCtrl)
	mockClinic.EXPECT().ListClinicsForPatientWithResponse(gomock.Any(), gomock.Eq(clinicClient.UserId("1111111111")), gomock.Any()).Return(&clinicClient.ListClinicsForPatientResponse{
		JSON200: &clinicClient.PatientClinicRelationships{},
		HTTPResponse: &http.Response{
			StatusCode: http.StatusOK,
		},
	}, nil)
	defer mockCtrl.Finish()

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"newpassword\", \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": false, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_UpdateUser_Success_Server_WithoutPassword(t *testing.T) {
	updatedUser := &User{
		Id:            "1111111111",
		Username:      "a@z.co",
		Emails:        []string{"a@z.co"},
		Roles:         []string{"clinic"},
		TermsAccepted: "2016-01-01T01:23:45-08:00",
		EmailVerified: true,
		Enabled:       true,
	}
	sessionToken := createSessionToken(t, "0000000000", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{updatedUser, nil}}
	mockNotifier.NotifyUserUpdatedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"roles\": [\"clinic\"], \"emailVerified\": true, \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "roles": []interface{}{"clinic"}, "termsAccepted": "2016-01-01T01:23:45-08:00", "passwordExists": false})
}

func Test_UpdateUser_Success_Server_WithPassword(t *testing.T) {
	updatedUser := &User{
		Id:            "1111111111",
		Username:      "a@z.co",
		Emails:        []string{"a@z.co"},
		Roles:         []string{"clinic"},
		TermsAccepted: "2016-01-01T01:23:45-08:00",
		EmailVerified: true,
		PwHash:        "newpasswordhash",
		Enabled:       true,
	}
	sessionToken := createSessionToken(t, "0000000000", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableStore.UpdateUserResponses = []UpdateUserResponse{{updatedUser, nil}}
	responsableGatekeeper.UsersInGroupResponses = []UsersPermissionsResponse{{clients.UsersPermissions{"0000000000": {"custodian": clients.Allowed}}, nil}}
	responsableGatekeeper.SetPermissionsResponses = []PermissionsResponse{{clients.Permissions{}, nil}}
	mockNotifier.NotifyUserUpdatedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	mockCtrl := gomock.NewController(t)
	mockClinic.Reset(mockCtrl)
	mockClinic.EXPECT().ListClinicsForPatientWithResponse(gomock.Any(), gomock.Eq(clinicClient.UserId("1111111111")), gomock.Any()).Return(&clinicClient.ListClinicsForPatientResponse{
		JSON200: &clinicClient.PatientClinicRelationships{},
		HTTPResponse: &http.Response{
			StatusCode: http.StatusOK,
		},
	}, nil)
	defer mockCtrl.Finish()

	body := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"a@z.co\"], \"password\": \"newpassword\", \"roles\": [\"clinic\"], \"emailVerified\": true, \"termsAccepted\": \"2016-01-01T01:23:45-08:00\"}}"
	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "PUT", "/user/1111111111", body, headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "roles": []interface{}{"clinic"}, "termsAccepted": "2016-01-01T01:23:45-08:00", "passwordExists": true})
}

////////////////////////////////////////////////////////////////////////////////

func Test_GetUserInfo_Error_MissingSessionToken(t *testing.T) {
	response := performRequest(t, "GET", "/user/1111111111")
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUserInfo_Error_FindUsersError(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/user/1111111111", headers)
	expectErrorResponse(t, response, 500, "Error finding user")
}

func Test_GetUserInfo_Error_FindUsersMissing(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{nil, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/user/1111111111", headers)
	expectErrorResponse(t, response, 404, "User not found")
}

func Test_GetUserInfo_Error_PermissionsError(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{}, errors.New("ERROR")}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/user/1111111111", headers)
	expectErrorResponse(t, response, 500, "Error finding user")
}

func Test_GetUserInfo_Error_NoPermissions(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"a": clients.Allowed}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/user/1111111111", headers)
	expectErrorResponse(t, response, 401, "Not authorized for requested operation")
}

func Test_GetUserInfo_Success_User(t *testing.T) {
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/user/1111111111", headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_GetUserInfo_Success_Custodian(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}, nil}}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/user/1111111111", headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
}

func Test_GetUserInfo_Success_Server(t *testing.T) {
	sessionToken := createSessionToken(t, "0000000000", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "GET", "/user/1111111111", headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00", "passwordExists": true})
}

////////////////////////////////////////////////////////////////////////////////

func TestDeleteUser_StatusForbidden_WhenNoPw(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@z.co", "").Return(nil, errors.New("invalid credentials"))
	defer mockCtrl.Finish()

	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "0000000000", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "DELETE", "/user/0000000000", headers)

	if response.Code != http.StatusForbidden {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusForbidden, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":403,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestDeleteUser_StatusForbidden_WhenEmptyPw(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@z.co", "").Return(nil, errors.New("invalid credentials"))
	defer mockCtrl.Finish()

	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "0000000000", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "DELETE", "/user/0000000000", `{"password":""}`, headers)

	if response.Code != http.StatusForbidden {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusForbidden, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":403,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestDeleteUser_StatusForbidden_WhenWrongPw(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@z.co", "incorrect").Return(nil, errors.New("invalid credentials"))
	defer mockCtrl.Finish()

	sessionToken := createSessionToken(t, "0000000000", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "0000000000", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "DELETE", "/user/0000000000", `{"password":"incorrect"}`, headers)

	if response.Code != http.StatusForbidden {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusForbidden, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != `{"code":403,"reason":"Missing id and/or password"}` {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestDeleteUser_StatusNoContentCustodian(t *testing.T) {
	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "0000000000", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "xyz", Hash: "123"}, nil}}
	responsableStore.AddTokenResponses = []error{nil}
	responsableGatekeeper.UserInGroupResponses = []PermissionsResponse{{clients.Permissions{"custodian": clients.Allowed}, nil}}
	mockNotifier.NotifyUserDeletedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "DELETE", "/user/0000000000", headers)

	if response.Code != http.StatusNoContent {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusNoContent, response.Code)
	}
}

func TestDeleteUser_StatusNoContentCorrectPassword(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@z.co", "password").Return(&oauth2.Token{AccessToken: "access_token"}, nil)
	defer mockCtrl.Finish()

	sessionToken := createSessionToken(t, "1111111111", false, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", Hash: "123"}, nil}}
	mockNotifier.NotifyUserDeletedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestBodyHeaders(t, "DELETE", "/user/1111111111", `{"password":"password"}`, headers)

	if response.Code != http.StatusNoContent {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusNoContent, response.Code)
	}
}

func TestDeleteUser_StatusNoContentWithServerToken(t *testing.T) {
	sessionToken := createSessionToken(t, "platform", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", Hash: "123"}, nil}}
	mockNotifier.NotifyUserDeletedResponses = []error{nil}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "DELETE", "/user/1111111111", headers)

	if response.Code != http.StatusNoContent {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusNoContent, response.Code)
	}
}

func TestDeleteUser_StatusUnauthorizedWhenClinic(t *testing.T) {
	sessionToken := createSessionToken(t, "platform", true, tokenDuration)
	responsableStore.FindTokenByIDResponses = []FindTokenByIDResponse{{sessionToken, nil}}
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, Roles: []string{"clinic"}, TermsAccepted: "2016-01-01T01:23:45-08:00", EmailVerified: true, PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", Hash: "123"}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add(TP_SESSION_TOKEN, sessionToken.ID)
	response := performRequestHeaders(t, "DELETE", "/user/1111111111", headers)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_Login_Error_MissingAuthorization(t *testing.T) {
	response := performRequest(t, "POST", "/login")
	expectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_Login_Error_EmptyAuthorization(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "")
	response := performRequestHeaders(t, "POST", "/login", headers)
	expectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_Login_Error_InvalidAuthorization(t *testing.T) {
	authorization := createAuthorization(t, "", "")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login", headers)
	expectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_Login_Error_LoginFailure(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@b.co", "password").Return(nil, errors.New("login error"))
	defer mockCtrl.Finish()

	authorization := createAuthorization(t, "a@b.co", "password")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login", headers)
	expectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_Login_Error_EmailNotVerified(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	token := oauth2.Token{AccessToken: "access_token", RefreshToken: "refresh_token"}
	introspectionResult := keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       "1111111111",
		EmailVerified: false,
	}
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@b.co", "password").Return(&token, nil)
	mockKeycloakClient.EXPECT().IntrospectToken(gomock.Any(), token).Return(&introspectionResult, nil)
	defer mockCtrl.Finish()

	authorization := createAuthorization(t, "a@b.co", "password")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login", headers)
	expectErrorResponse(t, response, 403, "The user hasn't verified this account yet")
}

func Test_Login_Success(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	token := oauth2.Token{AccessToken: "access_token", RefreshToken: "refresh_token"}
	introspectionResult := keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       "1111111111",
		EmailVerified: true,
	}
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@b.co", "password").Return(&token, nil)
	mockKeycloakClient.EXPECT().IntrospectToken(gomock.Any(), token).Return(&introspectionResult, nil)
	defer mockCtrl.Finish()

	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", EmailVerified: true}, nil}}
	defer expectResponsablesEmpty(t)

	authorization := createAuthorization(t, "a@b.co", "password")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login", headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
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
	request.Header.Set(TP_SERVER_SECRET, theSecret)
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
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	token := oauth2.Token{AccessToken: "service_access_token", RefreshToken: "service_refresh_token"}
	mockKeycloakClient.EXPECT().GetBackendServiceToken(gomock.Any()).Return(&token, nil)
	defer mockCtrl.Finish()

	request, _ := http.NewRequest("POST", "/serverlogin", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, theSecret)
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
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().GetBackendServiceToken(gomock.Any()).Return(nil, errors.New("error"))
	defer mockCtrl.Finish()

	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set(TP_SERVER_NAME, "shoreline")
	req.Header.Set(TP_SERVER_SECRET, theSecret)
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

func TestRefreshSession_StatusUnauthorized_WithNoToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.RefreshSession(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusUnauthorized_WithWrongToken(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().RefreshToken(gomock.Any(), gomock.Any()).Return(nil, errors.New("error"))
	defer mockCtrl.Finish()

	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, "kc:access:refresh")
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
	refreshRequest.Header.Set(TP_SESSION_TOKEN, userToken.ID)
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

	if tokenData.UserId != user.Id {
		t.Fatalf("should have had a user id of `%v` but was %v", user.Id, tokenData.UserId)
	}
}

func TestRefreshSession_Failure(t *testing.T) {

	shorelineFails.SetHandlers("", rtr)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set(TP_SESSION_TOKEN, userToken.ID)
	resp := httptest.NewRecorder()

	shorelineFails.RefreshSession(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusUnauthorized, resp.Code)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_LongTermLogin_Error_MissingAuthorization(t *testing.T) {
	response := performRequest(t, "POST", "/login/thelongtermkey")
	expectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_LongTermLogin_Error_EmptyAuthorization(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "")
	response := performRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	expectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_LongTermLogin_Error_InvalidAuthorization(t *testing.T) {
	authorization := createAuthorization(t, "", "")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	expectErrorResponse(t, response, 400, "Missing id and/or password")
}

func Test_LongTermLogin_Error_LoginError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@b.co", "MISMATCH").Return(nil, errors.New("login error"))
	defer mockCtrl.Finish()

	authorization := createAuthorization(t, "a@b.co", "MISMATCH")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	expectErrorResponse(t, response, 401, "No user matched the given details")
}

func Test_LongTermLogin_Error_EmailNotVerified(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	token := oauth2.Token{AccessToken: "access_token", RefreshToken: "refresh_token"}
	introspectionResult := keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       "1111111111",
		EmailVerified: false,
		ExpiresAt:     time.Now().Unix() + int64(time.Hour.Seconds()),
	}
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@b.co", "password").Return(&token, nil)
	mockKeycloakClient.EXPECT().IntrospectToken(gomock.Any(), token).Return(&introspectionResult, nil)
	defer mockCtrl.Finish()

	authorization := createAuthorization(t, "a@b.co", "password")
	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	expectErrorResponse(t, response, 403, "The user hasn't verified this account yet")
}

func Test_LongTermLogin_Success(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	token := oauth2.Token{AccessToken: "access_token", RefreshToken: "refresh_token"}
	introspectionResult := keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       "1111111111",
		EmailVerified: true,
	}
	mockKeycloakClient.EXPECT().Login(gomock.Any(), "a@b.co", "password").Return(&token, nil)
	mockKeycloakClient.EXPECT().IntrospectToken(gomock.Any(), token).Return(&introspectionResult, nil)
	defer mockCtrl.Finish()

	authorization := createAuthorization(t, "a@b.co", "password")
	responsableStore.FindUserResponses = []FindUserResponse{{&User{Id: "1111111111", Username: "a@z.co", Emails: []string{"a@z.co"}, TermsAccepted: "2016-01-01T01:23:45-08:00", PwHash: "d1fef52139b0d120100726bcb43d5cc13d41e4b5", EmailVerified: true}, nil}}
	defer expectResponsablesEmpty(t)

	headers := http.Header{}
	headers.Add("Authorization", authorization)
	response := performRequestHeaders(t, "POST", "/login/thelongtermkey", headers)
	successResponse := expectSuccessResponseWithJSONMap(t, response, 200)
	expectElementMatch(t, successResponse, "userid", `\A[0-9a-f]{10}\z`, true)
	expectEqualsMap(t, successResponse, map[string]interface{}{"emailVerified": true, "emails": []interface{}{"a@z.co"}, "username": "a@z.co", "termsAccepted": "2016-01-01T01:23:45-08:00"})
	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatalf("Missing expected %s header", TP_SESSION_TOKEN)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestServerCheckToken_StatusOK(t *testing.T) {

	//the api
	shoreline.SetHandlers("", rtr)

	token := oauth2.Token{
		AccessToken:  "server_access",
		RefreshToken: "server_refresh",
	}
	sessionToken := "kc:server_access:server_refresh"

	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	introspectionResult := keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       "shoreline",
		EmailVerified: true,
		RealmAccess:   keycloak.RealmAccess{Roles: []string{"backend_service"}},
		ExpiresAt:     time.Now().Unix() + int64(time.Hour.Seconds()),
	}
	mockKeycloakClient.EXPECT().IntrospectToken(gomock.Any(), token).Return(&introspectionResult, nil).Times(2)
	defer mockCtrl.Finish()

	//step 2 - do the check
	checkTokenRequest, _ := http.NewRequest("GET", "/", nil)
	checkTokenRequest.Header.Set(TP_SESSION_TOKEN, sessionToken)
	checkTokenResponse := httptest.NewRecorder()

	shoreline.ServerCheckToken(checkTokenResponse, checkTokenRequest, map[string]string{"token": sessionToken})

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

	shoreline.ServerCheckToken(response, request, noParams)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestCheckToken_StatusOK(t *testing.T) {

	//the api

	shoreline.SetHandlers("", rtr)
	token := oauth2.Token{
		AccessToken:  "server_access",
		RefreshToken: "server_refresh",
	}
	sessionToken := "kc:server_access:server_refresh"

	mockCtrl := gomock.NewController(t)
	mockKeycloakClient.Reset(mockCtrl)
	introspectionResult := keycloak.TokenIntrospectionResult{
		Active:        true,
		Subject:       "shoreline",
		EmailVerified: true,
		RealmAccess:   keycloak.RealmAccess{Roles: []string{"backend_service"}},
		ExpiresAt:     time.Now().Unix() + int64(time.Hour.Seconds()),
	}
	mockKeycloakClient.EXPECT().IntrospectToken(gomock.Any(), token).Return(&introspectionResult, nil)
	defer mockCtrl.Finish()

	//step 2 - do the check
	checkTokenRequest, _ := http.NewRequest("GET", "/", nil)
	checkTokenRequest.Header.Set(TP_SESSION_TOKEN, sessionToken)
	checkTokenResponse := httptest.NewRecorder()

	shoreline.CheckToken(checkTokenResponse, checkTokenRequest)

	if checkTokenResponse.Code != http.StatusOK {
		t.Fatalf("Expected status code %v:\n\tGot: %v", http.StatusOK, checkTokenResponse.Code)
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

func TestCheckToken_StatusUnauthorized_WhenNoToken(t *testing.T) {

	//the api

	shoreline.SetHandlers("", rtr)

	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	shoreline.CheckToken(response, request)

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
	request.Header.Set(TP_SESSION_TOKEN, userToken.ID)
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
	req.Header.Set(TP_SESSION_TOKEN, userToken.ID)
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

	var anonIDHashPair AnonIdHashPair
	_ = json.Unmarshal(body, &anonIDHashPair)

	if anonIDHashPair.Name != "" {
		t.Fatalf("should have no name but was %v", anonIDHashPair.Name)
	}
	if anonIDHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", anonIDHashPair.Id)
	}
	if anonIDHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", anonIDHashPair.Hash)
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

	var anonIDHashPair AnonIdHashPair
	_ = json.Unmarshal(body, &anonIDHashPair)

	if anonIDHashPair.Name != "" {
		t.Fatalf("should have no name but was %v", anonIDHashPair.Name)
	}
	if anonIDHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", anonIDHashPair.Id)
	}
	if anonIDHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", anonIDHashPair.Hash)
	}
}

////////////////////////////////////////////////////////////////////////////////

func TestAnonIdHashPair_InBulk(t *testing.T) {

	shoreline.SetHandlers("", rtr)

	// we ask for 100 AnonymousIdHashPair to be created
	//NOTE: while we can run more locally travis doesn't like it so 100 should be good enough
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

func Test_TokenUserHasRequestedPermissions_Server(t *testing.T) {
	tokenData := &TokenData{UserId: "abcdef1234", IsServer: true, DurationSecs: tokenDuration}
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
	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: tokenDuration}
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
	defer expectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: tokenDuration}
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
	defer expectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: tokenDuration}
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
	defer expectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: tokenDuration}
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
	defer expectResponsablesEmpty(t)

	tokenData := &TokenData{UserId: "abcdef1234", IsServer: false, DurationSecs: tokenDuration}
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
	defer expectResponsablesEmpty(t)

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
	defer expectResponsablesEmpty(t)

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
	defer expectResponsablesEmpty(t)

	err := responsableShoreline.removeUserPermissions("1", clients.Permissions{"a": clients.Allowed})
	if err != nil {
		t.Fatalf("Unexpected error: %#v", err)
	}
}

////////////////////////////////////////////////////////////////////////////////

func Test_DeleteUserSessions_Error_User(t *testing.T) {
	shorelineFails.SetHandlers("", rtr)
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("/user/%v/sessions", userToken.UserID), nil)
	req.Header.Set(TP_SESSION_TOKEN, userToken.ID)
	resp := httptest.NewRecorder()

	shoreline.DeleteUserSessions(resp, req, map[string]string{"userid": userToken.UserID})

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusUnauthorized, resp.Code)
	}
}

func Test_DeleteUserSessions_Success(t *testing.T) {
	shorelineFails.SetHandlers("", rtr)
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("/user/%v/sessions", userToken.UserID), nil)
	req.Header.Set(TP_SESSION_TOKEN, serverToken.ID)
	resp := httptest.NewRecorder()

	shoreline.DeleteUserSessions(resp, req, map[string]string{"userid": userToken.UserID})

	if resp.Code != http.StatusNoContent {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusNoContent, resp.Code)
	}
}
