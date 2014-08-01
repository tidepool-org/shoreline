package api

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/tidepool-org/shoreline/clients"
	"github.com/tidepool-org/shoreline/models"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	THE_SECRET = "shhh! don't tell"
)

var (
	NO_PARAMS  = map[string]string{}
	fakeConfig = config{
		ServerSecret: "shhh! don't tell",
		LongTermKey:  "the longetermkey",
		Salt:         "a mineral substance composed primarily of sodium chloride",
	}
)

func TestCreateUser_StatusBadRequest_WhenNoParamsGiven(t *testing.T) {

	request, _ := http.NewRequest("POST", "/user", nil)
	response := httptest.NewRecorder()

	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "400", response.Code)
	}
}

func TestCreateUser_StatusCreated(t *testing.T) {

	var jsonData = []byte(`{"username": "test", "password": "123youknoWm3","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("POST", "/user", bytes.NewBuffer(jsonData))
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()

	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "201", response.Code)
	}
}

func TestUpdateUser_StatusUnauthorized_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("PUT", "/user", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.UpdateUser(response, request, NO_PARAMS)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestUpdateUser_StatusBadRequest_WhenNoUpdates(t *testing.T) {
	request, _ := http.NewRequest("PUT", "/user", nil)
	request.Header.Add("content-type", "application/json")
	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.UpdateUser(response, request, NO_PARAMS)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "400", response.Code)
	}
}

func TestUpdateUser_StatusOK(t *testing.T) {

	/*
	 * can update all
	 */
	var updateAll = []byte(`{"userid":"0x3-123-345-0x3","username": "test","password":"aN3wPw0rD","emails":["test@new.bar"]}`)

	requestUpdateAll, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateAll))

	requestUpdateAll.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	requestUpdateAll.Header.Add("content-type", "application/json")

	responseUpdateAll := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.UpdateUser(requestUpdateAll, responseUpdateAll, NO_PARAMS)

	if responseUpdateAll.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", response.Code)
	}

	/*
	 * can update just username
	 */
	var updateName = []byte(`{"username": "Updated Name"}`)

	requestUpdateName, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateName))
	requestUpdateName.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	requestUpdateName.Header.Add("content-type", "application/json")
	responseUpdateName := httptest.NewRecorder()
	shoreline.UpdateUser(requestUpdateName, responseUpdateName, NO_PARAMS)

	if responseUpdateName.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", response.Code)
	}

	/*
	 * can update just pw
	 */

	var updatePW = []byte(`{"password": "MyN3w0n_"}`)

	requestUpdatePW, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updatePW))
	requestUpdatePW.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	requestUpdatePW.Header.Add("content-type", "application/json")
	responseUpdatePW := httptest.NewRecorder()
	shoreline.UpdateUser(requestUpdatePW, responseUpdatePW, NO_PARAMS)

	if responseUpdatePW.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", response.Code)
	}

	/*
	 * can update just email
	 */
	var updateEmail = []byte(`{"emails":["test@foo.bar","test@new.bar"]}`)

	requestUpdateEmail, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateEmail))
	requestUpdateEmail.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	requestUpdateEmail.Header.Add("content-type", "application/json")
	responseUpdateEmail := httptest.NewRecorder()
	shoreline.UpdateUser(requestUpdateEmail, responseUpdateEmail, NO_PARAMS)

	if responseUpdateEmail.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", response.Code)
	}

}

func TestGetUserInfo_StatusOK_AndBody(t *testing.T) {
	var findData = []byte(`{"username": "test","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findData))
	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	request.Header.Add("content-type", "application/json")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.GetUserInfo(response, request, NO_PARAMS)

	//NOTE: as we have mocked the mongo layer we just be passed back what we gave
	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Body == nil {
		t.Fatalf("Non-expected empty body has been returned body: %v", response.Body)
	}
}

func TestGetUserInfo_StatusOK_AndBody_WhenIdInURL(t *testing.T) {

	request, _ := http.NewRequest("GET", "/", nil)

	values := request.URL.Query()
	values.Add("userid", "9lJmBOVkWB")
	request.URL.RawQuery = values.Encode()

	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.GetUserInfo(response, request, NO_PARAMS)

	//NOTE: as we have mocked the mongo layer we just be passed back what we gave
	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Body == nil {
		t.Fatalf("Non-expected empty body has been returned body: %v", response.Body)
	}
}

func TestGetUserInfo_StatusUnauthorized_WhenNoToken(t *testing.T) {
	var findData = []byte(`{"username": "test","emails":["test@foo.bar"]}`)
	request, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findData))
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.GetUserInfo(response, request, NO_PARAMS)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestDeleteUserReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestDeleteUserReturns401WhenNoSessionTokenHeaderGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestLogin_StatusBadRequest_WithNoAuth(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.Login(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestLogin_StatusBadRequest_WithInvalidAuth(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("", "")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.Login(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestLogin_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.Login(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("The session token should have been set")
	}
}

func TestServerLogin_StatusBadRequest_WhenNoNameOrSecret(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestServerLogin_StatusBadRequest_WhenNoName(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestServerLogin_StatusBadRequest_WhenNoSecret(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestServerLogin_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("The session token should have been set")
	}
}

func TestServerLogin_StatusUnauthorized_WhenSecretWrong(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, "wrong secret")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusUnauthorized_WithNoToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
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
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.RefreshSession(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	//login to create a token first
	shoreline.Login(response, request)
	tokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if tokenToUse == "" {
		t.Fatalf("we expected to get a token back")
	}

	nextRequest, _ := http.NewRequest("GET", "/", nil)

	nextRequest.Header.Set(TP_SESSION_TOKEN, tokenToUse)

	shoreline.RefreshSession(response, nextRequest)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}
}

func TestValidateLongterm_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.LongtermLogin(response, request, NO_PARAMS)

	if response.Code != http.StatusOK {
		t.Fatalf("the status code should be %v set but got %v", http.StatusOK, response.Code)
	}

	if request.Header.Get(TP_TOKEN_DURATION) != "" {
		t.Fatal("there should be a token duration set")
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("The session token should have been set")
	}
}

func TestValidateLongterm_StatusBadRequest_AuthEmpty(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.SetBasicAuth("", "")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.LongtermLogin(response, request, NO_PARAMS)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("the status code should be %v set but got %v", http.StatusBadRequest, response.Code)
	}
}

func TestValidateLongterm_StatusUnauthorized_WithNoAuthSet(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.LongtermLogin(response, request, NO_PARAMS)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("the status code should be %v set but got %v", http.StatusBadRequest, response.Code)
	}
}

func TestRequireServerToken_ReturnsWithNoStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	//login as server
	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back")
	}

	//now do the check
	nextRequest, _ := http.NewRequest("GET", "/", nil)
	nextRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)

	shoreline.requireServerToken(response, nextRequest)

	if response.Code == 0 {
		t.Fatalf("expected no status code%v:\n\tbody: %v", response.Code)
	}
}

func TestRequireServerToken_StatusUnauthorized_WhenWrongTokenGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.requireServerToken(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRequireServerToken_StatusUnauthorized_WhenNoSessionTokenHeaderGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.requireServerToken(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestServerCheckToken_StatusOK(t *testing.T) {

	//the api
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
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

	body, _ := ioutil.ReadAll(checkTokenResponse.Body)

	var tokenData models.TokenData
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
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	shoreline.ServerCheckToken(response, request, NO_PARAMS)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestLogout_StatusOK_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.Logout(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}
}

func TestLogout_StatusOK(t *testing.T) {

	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	//login to create a token first
	shoreline.Login(response, request)
	tokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if tokenToUse == "" {
		t.Fatalf("we expected to get a token back")
	}
	//now logout with valid token
	nextRequest, _ := http.NewRequest("POST", "/", nil)
	nextRequest.Header.Set(TP_SESSION_TOKEN, tokenToUse)

	shoreline.Logout(response, nextRequest)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}
}

func TestAnonymousIdHashPair_StatusInternalServerError_NoParamsGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.AnonymousIdHashPair(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestAnonymousIdHashPair_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)

	values := request.URL.Query()
	values.Add("one", "somestuff")
	values.Add("two", "some more stuff")
	request.URL.RawQuery = values.Encode()

	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	shoreline.AnonymousIdHashPair(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	var anonIdHashPair models.AnonIdHashPair
	_ = json.Unmarshal(body, &anonIdHashPair)

	if anonIdHashPair.Name != "" {
		t.Fatalf("should have no name but was %v", anonIdHashPair.Name)
	}
	if anonIdHashPair.IdHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", anonIdHashPair.IdHashPair.Id)
	}
	if anonIdHashPair.IdHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", anonIdHashPair.IdHashPair.Hash)
	}
}

func TestManageIdHashPair_StatusUnauthorized_WhenNoSvrToken(t *testing.T) {

	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)

	request, _ := http.NewRequest("GET", "/1234/givemesomemore", nil)
	response := httptest.NewRecorder()

	shoreline.ManageIdHashPair(response, request, map[string]string{"userid": "1234", "key": "givemesomemore"})

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}

	postRequest, _ := http.NewRequest("POST", "/1234/givemesomemore", nil)
	postResponse := httptest.NewRecorder()

	shoreline.ManageIdHashPair(postResponse, postRequest, map[string]string{"userid": "1234", "key": "givemesomemore"})

	if postResponse.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, postResponse.Code)
	}

	putRequest, _ := http.NewRequest("PUT", "/1234/givemesomemore", nil)
	putResponse := httptest.NewRecorder()

	shoreline.ManageIdHashPair(putResponse, putRequest, map[string]string{"userid": "1234", "key": "givemesomemore"})

	if putResponse.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, putResponse.Code)
	}
}

func TestManageIdHashPair_StatusNotImplemented_WhenDelete(t *testing.T) {

	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)
	//server login
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back from login")
	}

	//step 2 - manage the pair
	mngIdPairRequest, _ := http.NewRequest("DELETE", "/1234/somename", nil)
	mngIdPairRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)
	mngIdPairResponse := httptest.NewRecorder()

	shoreline.ManageIdHashPair(mngIdPairResponse, mngIdPairRequest, map[string]string{"userid": "1234", "key": "givemesomemore"})

	if mngIdPairResponse.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusNotImplemented, response.Code)
	}
}

func TestManageIdHashPair_StatusOK(t *testing.T) {

	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)
	//server login
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back from login")
	}

	//step 2 - manage the pair
	mngIdPairRequest, _ := http.NewRequest("GET", "/1234/somename", nil)
	mngIdPairRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)

	shoreline.ManageIdHashPair(response, mngIdPairRequest, map[string]string{"userid": "1234", "key": "somename"})

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	var idHashPair models.IdHashPair
	_ = json.Unmarshal(body, &idHashPair)

	if idHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", idHashPair.Id)
	}
	if idHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", idHashPair.Hash)
	}
}

func TestManageIdHashPair_StatusCreated_WhenPost(t *testing.T) {

	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)
	//server login
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back from login")
	}

	//step 2 - manage the pair
	mngIdPairRequest, _ := http.NewRequest("POST", "/1234/somename", nil)
	mngIdPairRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)
	mngIdPairResponse := httptest.NewRecorder()

	shoreline.ManageIdHashPair(mngIdPairResponse, mngIdPairRequest, map[string]string{"userid": "1234", "key": "somename"})

	if mngIdPairResponse.Code != http.StatusCreated {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusCreated, response.Code)
	}

	body, _ := ioutil.ReadAll(mngIdPairResponse.Body)

	var idHashPair models.IdHashPair
	_ = json.Unmarshal(body, &idHashPair)

	if idHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", idHashPair.Id)
	}
	if idHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", idHashPair.Hash)
	}
}

func TestManageIdHashPair_StatusCreated_WhenPut(t *testing.T) {

	mockStore := clients.NewMockStoreClient(fakeConfig.Salt, false)
	rtr := mux.NewRouter()
	shoreline := InitApi(mockStore, fakeConfig)
	shoreline.SetHandlers("", rtr)
	//server login
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()

	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back from login")
	}

	//step 2 - manage the pair
	mngIdPairRequest, _ := http.NewRequest("PUT", "/1234/somename", nil)
	mngIdPairRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)
	mngIdPairResponse := httptest.NewRecorder()

	shoreline.ManageIdHashPair(mngIdPairResponse, mngIdPairRequest, map[string]string{"userid": "1234", "key": "somename"})

	if mngIdPairResponse.Code != http.StatusCreated {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusCreated, response.Code)
	}

	body, _ := ioutil.ReadAll(mngIdPairResponse.Body)

	var idHashPair models.IdHashPair
	_ = json.Unmarshal(body, &idHashPair)

	if idHashPair.Id == "" {
		t.Fatalf("should have an Id but was %v", idHashPair.Id)
	}
	if idHashPair.Hash == "" {
		t.Fatalf("should have an Hash but was %v", idHashPair.Hash)
	}
}
