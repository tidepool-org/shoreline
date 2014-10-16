package api

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"./../clients"
	"./../models"
	"github.com/tidepool-org/go-common/clients/highwater"
)

const (
	THE_SECRET   = "shhh! don't tell"
	MAKE_IT_FAIL = true
)

var (
	NO_PARAMS   = map[string]string{}
	FAKE_CONFIG = Config{
		ServerSecret: "shhh! don't tell",
		Secret:       "shhh! don't tell *2",
		LongTermKey:  "the longetermkey",
		Salt:         "a mineral substance composed primarily of sodium chloride",
	}
	/*
	 * users and tokens
	 */
	USR           = &models.User{Id: "123-99-100", Name: "Test One", Emails: []string{"test@new.bar"}}
	usrTknData    = &models.TokenData{UserId: USR.Id, IsServer: false, DurationSecs: 3600}
	USR_TOKEN, _  = models.NewSessionToken(usrTknData, FAKE_CONFIG.Secret)
	sverTknData   = &models.TokenData{UserId: "shoreline", IsServer: true, DurationSecs: 36000}
	SRVR_TOKEN, _ = models.NewSessionToken(sverTknData, FAKE_CONFIG.Secret)
	/*
	 * basics setup
	 */
	rtr = mux.NewRouter()
	/*
	 * expected path
	 */
	mockStore   = clients.NewMockStoreClient(FAKE_CONFIG.Salt, false, false)
	mockMetrics = highwater.NewMock()
	shoreline   = InitApi(FAKE_CONFIG, mockStore, mockMetrics)
	/*
	 *
	 */
	mockNoDupsStore = clients.NewMockStoreClient(FAKE_CONFIG.Salt, true, false)
	shorelineNoDups = InitApi(FAKE_CONFIG, mockNoDupsStore, mockMetrics)
	/*
	 * failure path
	 */
	mockStoreFails = clients.NewMockStoreClient(FAKE_CONFIG.Salt, false, MAKE_IT_FAIL)
	shorelineFails = InitApi(FAKE_CONFIG, mockStoreFails, mockMetrics)
)

func TestGetStatus_StatusOk(t *testing.T) {

	request, _ := http.NewRequest("GET", "/status", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.GetStatus(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Resp given [%s] expected [%s] ", response.Code, http.StatusOK)
	}

}

func TestGetStatus_StatusInternalServerError(t *testing.T) {

	request, _ := http.NewRequest("GET", "/status", nil)
	response := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.GetStatus(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("Resp given [%s] expected [%s] ", response.Code, http.StatusInternalServerError)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != "Session failure" {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), "Session failure")
	}

}

func TestCreateUser_StatusBadRequest_WhenNoParamsGiven(t *testing.T) {

	request, _ := http.NewRequest("POST", "/user", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "400", response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_MISSING_USR_DETAILS {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_USR_DETAILS)
	}

}

func TestCreateUser_StatusCreated(t *testing.T) {

	var jsonData = []byte(`{"username": "test", "password": "123youknoWm3","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("POST", "/user", bytes.NewBuffer(jsonData))
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()

	shorelineNoDups.SetHandlers("", rtr)

	shorelineNoDups.CreateUser(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "201", response.Code)
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("the resp should have a session token")
	}

	if response.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
	}

	body, _ := ioutil.ReadAll(response.Body)

	var usrData map[string]string
	_ = json.Unmarshal(body, &usrData)

	if usrData == nil {
		t.Fatal("body should have been returned")
	}

	if usrData["userid"] == "" {
		t.Fatal("body should have the userid")
	}

}

func TestCreateUser_Failure(t *testing.T) {

	var jsonData = []byte(`{"username": "test", "password": "123youknoWm3","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("POST", "/user", bytes.NewBuffer(jsonData))
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.CreateUser(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, response.Code)
	}
}

func TestCreateUser_StatusConflict_ForDuplicates(t *testing.T) {

	var jsonData = []byte(`{"username": "test", "password": "123youknoWm3","emails":["test@foo.bar"]}`)

	request, _ := http.NewRequest("POST", "/user", bytes.NewBuffer(jsonData))
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.CreateUser(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", http.StatusConflict, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_USR_ALREADY_EXISTS {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_USR_ALREADY_EXISTS)
	}

}

func TestUpdateUser_StatusUnauthorized_WhenNoToken(t *testing.T) {
	request, _ := http.NewRequest("PUT", "/user", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.UpdateUser(response, request, NO_PARAMS)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestUpdateUser_StatusBadRequest_WhenNoUpdates(t *testing.T) {
	request, _ := http.NewRequest("PUT", "/user", nil)
	request.Header.Add("content-type", "application/json")
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.UpdateUser(response, request, NO_PARAMS)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "400", response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_NO_USR_DETAILS {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_NO_USR_DETAILS)
	}
}

func TestUpdateUser_IdFromToken_StatusOK(t *testing.T) {

	shorelineNoDups.SetHandlers("", rtr)

	/*
	 * can update all
	 */
	var updateAll = []byte(`{"updates":{"username": "id from token","password":"aN3wPw0rD","emails":["fromtkn@new.bar"]}}`)

	requestUpdateAll, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateAll))

	requestUpdateAll.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	requestUpdateAll.Header.Add("content-type", "application/json")

	responseUpdateAll := httptest.NewRecorder()

	shorelineNoDups.UpdateUser(responseUpdateAll, requestUpdateAll, NO_PARAMS)

	if responseUpdateAll.Code != http.StatusOK {
		t.Fatalf("Status given [%v] expected [%v] ", responseUpdateAll.Code, http.StatusOK)
	}

}

func TestUpdateUser_StatusOK(t *testing.T) {

	shorelineNoDups.SetHandlers("", rtr)

	/*
	 * can update all
	 */
	var updateAll = []byte(`{"updates":{"username": "change1","password":"aN3wPw0rD","emails":["change1@new.bar"]}}`)

	requestUpdateAll, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateAll))

	requestUpdateAll.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	requestUpdateAll.Header.Add("content-type", "application/json")

	responseUpdateAll := httptest.NewRecorder()

	shorelineNoDups.UpdateUser(responseUpdateAll, requestUpdateAll, map[string]string{"userid": USR.Id})

	if responseUpdateAll.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", responseUpdateAll.Code)
	}

	/*
	 * can update just username
	 */
	var updateName = []byte(`{"updates":{"username": "change2"}}`)

	requestUpdateName, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateName))
	requestUpdateName.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	requestUpdateName.Header.Add("content-type", "application/json")
	responseUpdateName := httptest.NewRecorder()
	shorelineNoDups.UpdateUser(responseUpdateName, requestUpdateName, map[string]string{"userid": USR.Id})

	if responseUpdateName.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", responseUpdateName.Code)
	}

	/*
	 * can update just pw
	 */

	var updatePW = []byte(`{"updates":{"password": "MyN3w0n_"}}`)

	requestUpdatePW, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updatePW))
	requestUpdatePW.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	requestUpdatePW.Header.Add("content-type", "application/json")
	responseUpdatePW := httptest.NewRecorder()
	shorelineNoDups.UpdateUser(responseUpdatePW, requestUpdatePW, map[string]string{"userid": USR.Id})

	if responseUpdatePW.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", responseUpdatePW.Code)
	}

	/*
	 * can update just email
	 */
	var updateEmail = []byte(`{"updates":{"emails":["change3@new.bar"]}}`)

	requestUpdateEmail, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateEmail))
	requestUpdateEmail.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	requestUpdateEmail.Header.Add("content-type", "application/json")
	responseUpdateEmail := httptest.NewRecorder()
	shorelineNoDups.UpdateUser(responseUpdateEmail, requestUpdateEmail, map[string]string{"userid": USR.Id})

	if responseUpdateEmail.Code != http.StatusOK {
		t.Fatalf("Non-expected status code %v:\n\tbody: %v", "200", responseUpdateEmail.Code)
	}

}

func TestUpdateUser_Failure(t *testing.T) {

	var updateAll = []byte(`{"updates":{"username": "change1","password":"aN3wPw0rD","emails":["change1@new.bar"]}}`)

	req, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateAll))
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	req.Header.Add("content-type", "application/json")

	resp := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)
	shorelineFails.UpdateUser(resp, req, map[string]string{"userid": USR.Id})

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}
}

func TestGetUserInfo_StatusOK_AndBody(t *testing.T) {
	var findData = []byte(`{"updates":{"username": "test","emails":["test@foo.bar"]}}`)

	request, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findData))
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	request.Header.Add("content-type", "application/json")
	response := httptest.NewRecorder()

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

func TestGetUserInfo_Failure(t *testing.T) {
	var findData = []byte(`{"updates":{"username": "test","emails":["test@foo.bar"]}}`)

	req, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findData))
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	req.Header.Add("content-type", "application/json")
	resp := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)
	shorelineFails.GetUserInfo(resp, req, NO_PARAMS)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}

}

func TestGetUserInfo_StatusOK_AndBody_WhenIdInURL(t *testing.T) {

	request, _ := http.NewRequest("GET", "/", nil)

	values := request.URL.Query()
	values.Add("userid", "9lJmBOVkWB")
	request.URL.RawQuery = values.Encode()

	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()

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

func TestGetUserInfo_IsCaseInsensitive(t *testing.T) {

	/*
	 * Email
	 */
	var findData = []byte(`{emails":["TEST@FOO.BAR"]}`)
	requestEmail, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findData))

	requestEmail.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	requestEmail.Header.Add("content-type", "application/json")

	responseEmail := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.GetUserInfo(responseEmail, requestEmail, NO_PARAMS)

	//NOTE: as we have mocked the mongo layer we just be passed back what we gave
	if responseEmail.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, responseEmail.Code)
	}

	if responseEmail.Body == nil {
		t.Fatalf("Non-expected empty body has been returned body: %v", responseEmail.Body)
	}

	/*
	 * Email
	 */
	var findName = []byte(`{username":"TEST"}`)
	requestName, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findName))

	requestName.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	requestName.Header.Add("content-type", "application/json")

	responseName := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.GetUserInfo(responseName, requestName, NO_PARAMS)

	//NOTE: as we have mocked the mongo layer we just be passed back what we gave
	if responseName.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, responseName.Code)
	}

	if responseName.Body == nil {
		t.Fatalf("Non-expected empty body has been returned body: %v", responseName.Body)
	}
}

func TestGetUserInfo_StatusUnauthorized_WhenNoToken(t *testing.T) {
	var findData = []byte(`{"username": "test","emails":["test@foo.bar"]}`)
	request, _ := http.NewRequest("GET", "/", bytes.NewBuffer(findData))
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.GetUserInfo(response, request, NO_PARAMS)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "401", response.Code)
	}
}

func TestDeleteUser_StatusForbidden_WhenNoPw(t *testing.T) {
	request, _ := http.NewRequest("DELETE", "/", nil)
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request, NO_PARAMS)

	if response.Code != http.StatusForbidden {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusForbidden, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_MISSING_ID_PW {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestDeleteUser_StatusForbidden_WhenEmptyPw(t *testing.T) {

	var jsonData = []byte(`{"password": ""}`)
	request, _ := http.NewRequest("DELETE", "/", bytes.NewBuffer(jsonData))
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.DeleteUser(response, request, NO_PARAMS)

	if response.Code != http.StatusForbidden {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusForbidden, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_MISSING_ID_PW {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestDeleteUser_Failure(t *testing.T) {

	var jsonData = []byte(`{"password": "92ggh38"}`)
	req, _ := http.NewRequest("DELETE", "/", bytes.NewBuffer(jsonData))
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	resp := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.DeleteUser(resp, req, NO_PARAMS)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}
}

func TestDeleteUser_StatusAccepted(t *testing.T) {

	var jsonData = []byte(`{"password": "123youknoWm3"}`)
	request, _ := http.NewRequest("DELETE", "/", bytes.NewBuffer(jsonData))
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
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

func TestLogin_StatusBadRequest_WithNoAuth(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.Login(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_MISSING_ID_PW {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestLogin_StatusBadRequest_WithInvalidAuth(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("", "")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.Login(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_MISSING_ID_PW {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestLogin_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.Login(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusOK, response.Code)
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("The session token should have been set")
	}

	if response.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
	}
}

func TestLogin_Failure(t *testing.T) {
	req, _ := http.NewRequest("POST", "/", nil)
	req.SetBasicAuth("test", "123youknoWm3")
	resp := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.Login(resp, req)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}
}

func TestLogin_StatusUnauthorized_WhenWrongCreds(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	request.SetBasicAuth("test", "")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.Login(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusUnauthorized, response.Code)
	}
}

func TestServerLogin_StatusBadRequest_WhenNoNameOrSecret(t *testing.T) {
	request, _ := http.NewRequest("POST", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.ServerLogin(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", http.StatusBadRequest, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_MISSING_ID_PW {
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

	if string(body) != STATUS_MISSING_ID_PW {
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

	if string(body) != STATUS_MISSING_ID_PW {
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

	if string(body) != STATUS_PW_WRONG {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_PW_WRONG)
	}
}

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
	refreshRequest.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
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

	var tokenData models.TokenData
	_ = json.Unmarshal(body, &tokenData)

	if tokenData.UserId != USR.Id {
		t.Fatalf("should have had a user id of `%v` but was %v", USR.Id, tokenData.UserId)
	}
}

func TestRefreshSession_Failure(t *testing.T) {

	shorelineFails.SetHandlers("", rtr)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
	resp := httptest.NewRecorder()

	shorelineFails.RefreshSession(resp, req)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}
}

func TestValidateLongterm_StatusOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.SetBasicAuth("test", "123youknoWm3")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.LongtermLogin(response, request, map[string]string{"longtermkey": FAKE_CONFIG.LongTermKey})

	if response.Code != http.StatusOK {
		t.Fatalf("the status code should be %v set but got %v", http.StatusOK, response.Code)
	}

	if response.Header().Get(TP_TOKEN_DURATION) != "" {
		t.Fatal("there should be a token duration set")
	}

	if response.Header().Get(TP_SESSION_TOKEN) == "" {
		t.Fatal("The session token should have been set")
	}
}

func TestValidateLongterm_Failure(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.SetBasicAuth("test", "123youknoWm3")
	resp := httptest.NewRecorder()

	shorelineFails.SetHandlers("", rtr)

	shorelineFails.LongtermLogin(resp, req, map[string]string{"longtermkey": FAKE_CONFIG.LongTermKey})

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}
}

func TestValidateLongterm_StatusBadRequest_AuthEmpty(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	request.SetBasicAuth("", "")
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.LongtermLogin(response, request, NO_PARAMS)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("the status code should be %v set but got %v", http.StatusBadRequest, response.Code)
	}

	body, _ := ioutil.ReadAll(response.Body)

	if string(body) != STATUS_MISSING_ID_PW {
		t.Fatalf("Message given [%s] expected [%s] ", string(body), STATUS_MISSING_ID_PW)
	}
}

func TestValidateLongterm_StatusUnauthorized_WithNoAuthSet(t *testing.T) {
	request, _ := http.NewRequest("GET", "/", nil)
	response := httptest.NewRecorder()

	shoreline.SetHandlers("", rtr)

	shoreline.LongtermLogin(response, request, NO_PARAMS)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("the status code should be %v set but got %v", http.StatusBadRequest, response.Code)
	}
}

func TestHasServerToken_False_WhenWrongTokenGiven(t *testing.T) {

	shoreline.SetHandlers("", rtr)

	if shoreline.hasServerToken(USR_TOKEN.Id) {
		t.Fatal("No server token was give so should have failed")
	}
}

func TestHasServerToken_False_WhenUserTokenGiven(t *testing.T) {

	shoreline.SetHandlers("", rtr)

	if shoreline.hasServerToken("not this token") {
		t.Fatal("No server token was give so should have failed")
	}
}

func TestHasServerToken_False_WhenNoSessionTokenHeaderGiven(t *testing.T) {

	shoreline.SetHandlers("", rtr)

	if shoreline.hasServerToken("") {
		t.Fatal("No server token was give so should have failed")
	}
}

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

	if shoreline.hasServerToken(response.Header().Get(TP_SESSION_TOKEN)) == false {
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
	request.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
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
	req.Header.Set(TP_SESSION_TOKEN, USR_TOKEN.Id)
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

	var anonIdHashPair models.AnonIdHashPair
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

	var anonIdHashPair models.AnonIdHashPair
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

func TestManageIdHashPair_StatusUnauthorized_WhenNoSvrToken(t *testing.T) {

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

	if response.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
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

func TestManageIdHashPair_Failure(t *testing.T) {

	shorelineFails.SetHandlers("", rtr)

	req, _ := http.NewRequest("GET", "/1234/somename", nil)
	req.Header.Set(TP_SESSION_TOKEN, SRVR_TOKEN.Id)
	resp := httptest.NewRecorder()

	shorelineFails.ManageIdHashPair(resp, req, map[string]string{"userid": "1234", "key": "somename"})

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusInternalServerError, resp.Code)
	}
}

func TestManageIdHashPair_StatusCreated_WhenPost(t *testing.T) {

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

	if mngIdPairResponse.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
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

	if mngIdPairResponse.Header().Get("content-type") != "application/json" {
		t.Fatal("the resp should be json")
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
