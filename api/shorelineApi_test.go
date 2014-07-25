package api

import (
	"bytes"
	"encoding/json"
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

func TestCreateUser_StatusBadRequest_WhenNoParamsGiven(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	response := httptest.NewRecorder()

	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "400", response.Code)
	}
}

func TestCreateUser_StatusCreated(t *testing.T) {

	var jsonData = []byte(`{"username": "test", "password": "123youknoWm3","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("POST", "/", bytes.NewBuffer(jsonData))
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()

	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "201", response.Code)
	}
}

func TestUpdateUser_StatusUnauthorized_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("PUT", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.UpdateUser(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestUpdateUser_StatusBadRequest_WhenNoUpdates(t *testing.T) {
	request, _ := http.NewRequest("PUT", "/", nil)
	request.Header.Add("content-type", "application/json")
	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.UpdateUser(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "400", response.Code)
	}
}

func TestUpdateUser_StatusOK(t *testing.T) {

	var updateData = []byte(`{"userid":"0x3-123-345-0x3","username": "test","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("PUT", "/", bytes.NewBuffer(updateData))

	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.UpdateUser(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", response.Code)
	}
}

func TestGetUserInfo_StatusOK_AndBody(t *testing.T) {
	var findData = []byte(`{"username": "test","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findData))
	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	request.Header.Add("content-type", "application/json")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.GetUserInfo(response, request)

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
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.GetUserInfo(response, request)

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
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.GetUserInfo(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestDeleteUserReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, "blah-blah-123-blah")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.DeleteUser(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestDeleteUserReturns401WhenNoSessionTokenHeaderGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.DeleteUser(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestLogin_StatusBadRequest_WithNoAuth(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.Login(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestLogin_StatusBadRequest_WithInvalidAuth(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("", "")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.Login(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestLogin_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

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
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestServerLogin_StatusBadRequest_WhenNoName(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}
}

func TestServerLogin_StatusBadRequest_WhenNoSecret(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

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
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

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
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusUnauthorized_WithNoToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.RefreshSession(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusUnauthorized_WithWrongToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, "not this token")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.RefreshSession(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRefreshSession_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

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

func TestValidateLongtermReturnsWithStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ValidateLongterm(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "501", response.Code)
	}
}

func TestRequireServerToken_ReturnsWithNoStatus(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	//login as server
	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back")
	}

	//now do the check
	nextRequest, _ := http.NewRequest("GET", "/", nil)
	nextRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)

	shoreline.RequireServerToken(response, nextRequest)

	if response.Code == 0 {
		t.Fatalf("expected no status code%v:\n\tbody: %v", response.Code)
	}
}

func TestRequireServerToken_StatusUnauthorized_WhenWrongTokenGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.RequireServerToken(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestRequireServerToken_StatusUnauthorized_WhenNoSessionTokenHeaderGiven(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.RequireServerToken(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestServerCheckToken_StatusNotFound_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ServerCheckToken(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusNotFound, response.Code)
	}
}

func TestServerCheckToken_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)

	request.Header.Set(TP_SERVER_NAME, "shoreline")
	request.Header.Set(TP_SERVER_SECRET, THE_SECRET)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	//login as server
	shoreline.ServerLogin(response, request)

	svrTokenToUse := response.Header().Get(TP_SESSION_TOKEN)

	if svrTokenToUse == "" {
		t.Fatalf("we expected to get a token back")
	}

	//now do the check
	nextRequest, _ := http.NewRequest("GET", "/", nil)
	nextRequest.Header.Set(TP_SESSION_TOKEN, svrTokenToUse)

	shoreline.ServerCheckToken(response, nextRequest)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	var tokenData models.TokenData
	_ = json.Unmarshal(body, &tokenData)

	if tokenData.UserId != "shoreline" {
		t.Fatalf("should have had a server id of `shoreline` but was %v", tokenData.UserId)
	}

	if tokenData.IsServer != true {
		t.Fatalf("should have been a server token but was %v", tokenData.IsServer)
	}
}

func TestLogout_StatusOK_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.Logout(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}
}

func TestLogout_StatusOK(t *testing.T) {

	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

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
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

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
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

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

func TestManageIdHashPair(t *testing.T) {
	/*
			{ path: '/private/:userid/:key/', verbs: ['get', 'post', 'del', 'put'],
		      func: [requireServerToken, manageIdHashPair] }
	*/
	request, _ := http.NewRequest("GET", "/1234/somename", nil)

	response := httptest.NewRecorder()
	mockStore := clients.NewMockStoreClient()
	shoreline := InitApi(mockStore)

	shoreline.ManageIdHashPair(response, request)

	if response.Code != http.StatusNotImplemented {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusNotImplemented, response.Code)
	}
}
