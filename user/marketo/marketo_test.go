package marketo_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"

	"testing"

	"github.com/mdblp/shoreline/user/marketo"
)

func Test_Config_Validate_Missing(t *testing.T) {
	var config *marketo.Config
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "marketo: config is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_URL_Missing(t *testing.T) {
	config := NewTestConfig(t, MockServer(t))
	config.URL = ""
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "marketo: url is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}
func Test_Config_Validate_ID_Missing(t *testing.T) {
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	config.ID = ""
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "marketo: ID is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}
func Test_Config_Validate_APIKey_Missing(t *testing.T) {
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	config.Secret = ""
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "marketo: secret is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_ClinicRole_Missing(t *testing.T) {
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	config.ClinicRole = ""
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "marketo: clinic role is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_PatientRole_Missing(t *testing.T) {
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	config.PatientRole = ""
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "marketo: patient role is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}
func Test_Config_Validate_Timeout_error(t *testing.T) {
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	config.Timeout = 0
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "marketo: timeout error" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}
func Test_Config_Validate_Success(t *testing.T) {
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_NewManager_Logger_Missing(t *testing.T) {
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	manager, err := marketo.NewManager(nil, config)

	if manager.IsAvailable() {
		t.Fatal("NewManager returned manager when error expected")
	}
	if err == nil {
		t.Fatal("NewManager returned successfully when error expected")
	}
	if err.Error() != "marketo: logger is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Config_Invalid(t *testing.T) {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	config.URL = ""
	manager, err := marketo.NewManager(logger, config)
	if manager.IsAvailable() {
		t.Fatal("NewManager returned manager when error expected")
	}
	if err == nil {
		t.Fatal("NewManager returned successfully when error expected")
	}
	if err.Error() != "marketo: config is not valid; marketo: url is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Success(t *testing.T) {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	manager, err := marketo.NewManager(logger, config)
	if manager == nil {
		t.Fatal("NewManager did not return manager when success expected")
	}
	if err != nil {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_CreateListMembershipForUser_User_Missing(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	manager.CreateListMembershipForUser(nil)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_User_Email_Missing(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "" }
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_User_Email_Tidepool_Io(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.io" }
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_User_Email_Tidepool_Org(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.org" }
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_NewUser_Match_Personal(t *testing.T) {
	getResponseSuccess := `{
		"requestId":"1000",
		"result":[],
		"success":true
	}`
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		called++
		if called == 1 {
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}

			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		}
		if called == 2 {
			if r.URL.EscapedPath() != "/rest/v1/leads.json" {
				t.Errorf("Expected path to be /rest/v1/leads.json, got %s", r.URL.EscapedPath())
			}

			// check query params
			params, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				t.Errorf("Error parsing query params: %v", err)
			}
			checkParam(t, params, "fields", "email,id")
			checkParam(t, params, "filterType", "email")
			checkParam(t, params, "filterValues", "tester@example.com")
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}
			w.Write([]byte(getResponseSuccess))
		}
	}))
	defer ts.Close()
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	config := NewTestConfig(t, ts)
	manager, _ := marketo.NewManager(logger, config)
	var s = manager.(*marketo.Connector)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "tester@example.com" }
	newUserMock.IsClinicStub = func() bool { return false }
	s.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	user := s.TypeForUser(newUserMock)
	if user != "user" {
		t.Errorf("Expected '%v', got 'clinic'", user)
	}
}
func Test_CreateListMembershipForUser_NewUser_Match_Clinic(t *testing.T) {
	getResponseSuccess := `{
		"requestId":"1000",
		"result":[],
		"success":true
	}`
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		called++
		if called == 1 {
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}

			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		}
		if called == 2 {
			if r.URL.EscapedPath() != "/rest/v1/leads.json" {
				t.Errorf("Expected path to be /rest/v1/leads.json, got %s", r.URL.EscapedPath())
			}

			// check query params
			params, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				t.Errorf("Error parsing query params: %v", err)
			}
			checkParam(t, params, "fields", "email,id")
			checkParam(t, params, "filterType", "email")
			checkParam(t, params, "filterValues", "tester@example.com")
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}
			w.Write([]byte(getResponseSuccess))
		}
	}))
	defer ts.Close()
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	config := NewTestConfig(t, ts)
	manager, _ := marketo.NewManager(logger, config)
	var s = manager.(*marketo.Connector)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "tester@example.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	s.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	user := s.TypeForUser(newUserMock)
	if user != "clinic" {
		t.Errorf("Expected '%v', got 'user'", user)
	}
}
func Test_UpdateListMembershipForUser_OldUser_Missing(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	manager.UpdateListMembershipForUser(nil, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Missing(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	manager.UpdateListMembershipForUser(oldUserMock, nil)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Match_Personal(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	var s = manager.(*marketo.Connector)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "ten@sample.com" }
	oldUserMock.IsClinicStub = func() bool { return false }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "ten@sample.com" }
	newUserMock.IsClinicStub = func() bool { return false }
	s.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	user := s.TypeForUser(newUserMock)
	if user != "user" {
		t.Errorf("Expected '%v', got 'clinic'", user)
	}
}

func Test_UpdateListMembershipForUser_NewUser_Match_Clinic(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	var s = manager.(*marketo.Connector)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "eleven@sample.com" }
	oldUserMock.IsClinicStub = func() bool { return true }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "eleven@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	s.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	user := s.TypeForUser(newUserMock)
	if user != "clinic" {
		t.Errorf("Expected '%v', got 'user'", user)
	}
}

func Test_UpdateListMembershipForUser_NewUser_Email_Missing(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twelve@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "" }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Email_Tidepool_Io(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twelve@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.io" }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Email_Tidepool_Org(t *testing.T) {
	manager := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twelve@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.org" }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

const (
	createLeadResponseSuccess = `{
		"requestId":"1000",
		"result":[{"id":12345,"status":"created"}],
		"success":true
	}`
	updateLeadResponseSuccess = `{
		"requestId":"1000",
		"result":[{"id":23,"status":"updated"}],
		"success":true
	}`
	createLeadRequest = `{
		"action":"createOnly",
		"lookupField":"email",
		"input": [{"email": "%s", "firstName": "%s", "lastName": "%s", "userType": "%s"}]
	}`
	updateLeadRequest = `{
		"action":"updateOnly",
		"lookupField":"ID",
		"input": [{"email": "%s", "firstName": "%s", "lastName": "%s", "userType": "%s"}]
	}`
)

type CreateLeadRequest struct {
	Action      string `json:"action"`
	LookupField string `json:"lookupField"`
	Input       []struct {
		ID        int    `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		UserType  string `json:"userType"`
	} `json:"input"`
}

func Test_UpdateListMember(t *testing.T) {
	getResponseSuccess := `{
		"requestId":"1000",
		"result":[{"id":23,"email":"tester@example.com"}],
		"success":true
	}`
	path := "/rest/v1/leads.json"
	email := "tester@example.com"
	newEmail := "newtester@example.com"
	userType := "clinic"
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		called++
		if called == 1 {
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}

			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		}
		if called == 2 {
			if r.URL.EscapedPath() != "/rest/v1/leads.json" {
				t.Errorf("Expected path to be /rest/v1/leads.json, got %s", r.URL.EscapedPath())
			}

			// check query params
			params, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				t.Errorf("Error parsing query params: %v", err)
			}
			checkParam(t, params, "fields", "email,id")
			checkParam(t, params, "filterType", "email")
			checkParam(t, params, "filterValues", "tester@example.com")
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}
			w.Write([]byte(getResponseSuccess))
		}
		if called == 3 {
			// check path
			if r.URL.EscapedPath() != path {
				t.Errorf("Expected path to be %s, got %s", path, r.URL.EscapedPath())
			}

			// check method
			if r.Method != "POST" {
				t.Errorf("Expected 'POST' request, got '%s'", r.Method)
			}

			// check body
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			var requestBody CreateLeadRequest
			if err := json.Unmarshal(body, &requestBody); err != nil {
				t.Error(err)
			}
			if len(requestBody.Input) != 1 {
				t.Errorf("Expected one lead, got %d", len(requestBody.Input))
			}
			if requestBody.Action != "updateOnly" {
				t.Errorf("Expected 'updateOnly', got %s", requestBody.Action)
			}
			if requestBody.LookupField != "id" {
				t.Errorf("Expected 'id', got %s", requestBody.LookupField)
			}
			if requestBody.Input[0].Email != newEmail {
				t.Errorf("Expected %s, got %s", newEmail, requestBody.Input[0].Email)
			}
			if requestBody.Input[0].UserType != userType {
				t.Errorf("Expected %s, got %s", userType, requestBody.Input[0].UserType)
			}
			w.Write([]byte(updateLeadResponseSuccess))
		}
	}))
	defer ts.Close()
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	config := NewTestConfig(t, ts)
	manager, _ := marketo.NewManager(logger, config)
	var s = manager.(*marketo.Connector)
	var addOrUpdateMember = s.UpsertListMember(userType, email, newEmail)
	if addOrUpdateMember != nil {
		t.Error("Expected nil, returned not nil")
	}
}
func Test_CreateListMember(t *testing.T) {
	getResponseSuccess := `{
		"requestId":"1000",
		"result":[],
		"success":true
	}`
	path := "/rest/v1/leads.json"
	email := "tester@example.com"
	newEmail := "newtester@example.com"
	userType := "user"
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		called++
		if called == 1 {
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}

			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		}
		if called == 2 {
			if r.URL.EscapedPath() != "/rest/v1/leads.json" {
				t.Errorf("Expected path to be /rest/v1/leads.json, got %s", r.URL.EscapedPath())
			}

			// check query params
			params, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				t.Errorf("Error parsing query params: %v", err)
			}
			checkParam(t, params, "fields", "email,id")
			checkParam(t, params, "filterType", "email")
			checkParam(t, params, "filterValues", "tester@example.com")
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}
			w.Write([]byte(getResponseSuccess))
		}
		if called == 3 {
			// check path
			if r.URL.EscapedPath() != path {
				t.Errorf("Expected path to be %s, got %s", path, r.URL.EscapedPath())
			}

			// check method
			if r.Method != "POST" {
				t.Errorf("Expected 'POST' request, got '%s'", r.Method)
			}

			// check body
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			var requestBody CreateLeadRequest
			if err := json.Unmarshal(body, &requestBody); err != nil {
				t.Error(err)
			}
			if len(requestBody.Input) != 1 {
				t.Errorf("Expected one lead, got %d", len(requestBody.Input))
			}
			if requestBody.Action != "createOnly" {
				t.Errorf("Expected 'createOnly', got %s", requestBody.Action)
			}
			if requestBody.LookupField != "email" {
				t.Errorf("Expected 'email', got %s", requestBody.LookupField)
			}
			if requestBody.Input[0].Email != newEmail {
				t.Errorf("Expected %s, got %s", newEmail, requestBody.Input[0].Email)
			}
			if requestBody.Input[0].UserType != userType {
				t.Errorf("Expected %s, got %s", userType, requestBody.Input[0].UserType)
			}
			w.Write([]byte(createLeadResponseSuccess))
		}
	}))
	defer ts.Close()
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	config := NewTestConfig(t, ts)
	manager, _ := marketo.NewManager(logger, config)
	var s = manager.(*marketo.Connector)
	var addOrUpdateMember = s.UpsertListMember(userType, email, newEmail)
	if addOrUpdateMember != nil {
		t.Error("Expected nil, returned not nil")
	}
}
func Test_FindLead(t *testing.T) {
	getResponseSuccess := `{
		"requestId":"1000",
		"result":[{"id":23,"email":"tester@example.com"}],
		"success":true
	}`
	findLeadPath := "/rest/v1/leads.json?filterType=email&fields=email,id&filterValues=tester@example.com"
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if called == 0 {
			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		} else {
			// check path
			if r.URL.EscapedPath() != "/rest/v1/leads.json" {
				t.Errorf("Expected path to be /rest/v1/leads.json, got %s", r.URL.EscapedPath())
			}

			// check query params
			params, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				t.Errorf("Error parsing query params: %v", err)
			}
			checkParam(t, params, "filterType", "email")
			checkParam(t, params, "fields", "email,id")
			checkParam(t, params, "filterValues", "tester@example.com")
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}
			w.Write([]byte(getResponseSuccess))
		}
		called++

	}))
	defer ts.Close()
	config := NewTestConfig(t, ts)
	client, err := marketo.Client(marketo.Miniconfig(config))
	if err != nil {
		t.Error(err)
	}
	response, err := client.Get(findLeadPath)
	if err != nil {
		t.Error(err)
	}
	if !response.Success {
		t.Error(response.Errors)
	}
	var leads []marketo.LeadResult
	if err = json.Unmarshal(response.Result, &leads); err != nil {
		log.Fatal(err)
	}
	if len(leads) == 0 {
		t.Error("Lead is empty")
	}
	if len(leads) != 1 {
		t.Error("Lead does not exist")
	}
	if leads[0].ID != 23 {
		t.Error("Failed to find lead")
	}
}
func Test_FindLeadWithNoBody(t *testing.T) {
	invalidFindLeadPath := "/rest/v1leads.json?filterType=email&fields=email,id&filterValues=tester@example.com"
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if called == 0 {
			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		}
		called++

	}))
	defer ts.Close()
	config := NewTestConfig(t, ts)
	client, err := marketo.Client(marketo.Miniconfig(config))
	if err != nil {
		t.Error(err)
	}
	_, err = client.Get(invalidFindLeadPath)
	if err != nil {
		if called != 2 {
			t.Errorf("Expected only two calls: %d", called)
		}
		expectedError := fmt.Sprintf("No body! Check URL: %s%s", ts.URL, invalidFindLeadPath)
		if err.Error() != expectedError {
			t.Errorf("Expected %s, got %s", expectedError, err)
		}
		return
	}
	t.Error("Expectation not met")
}

const (
	clientID            = "1111"
	clientSecret        = "aaaa"
	token               = "aaaa-bbbb-cccc"
	authResponseSuccess = `{
		"access_token":"%s",
		"token_type":"bearer",
		"expires_in":3599,
		"scope":"tester@example.com"
	}`
	authResponseExpiringSuccess = `{
		"access_token":"%s",
		"token_type":"bearer",
		"expires_in":1,
		"scope":"tester@example.com"
	}`
	authResponseError = `{
		"error":"invalid_client",
		"error_description":"Bad client credentials"
	}`
	tokenExpiredResponse = `{
		"requestId":"1000",
		"success":false,
		"errors":[{"code":"602","message":"Access token expired"}]
	}`
	invalidTokenResponse = `{
		"requestId":"1000",
		"success":false,
		"errors":[{"code":"601","message":"Access token invalid"}]
	}`
)

func checkParam(t *testing.T, params url.Values, key, expected string) {
	if params[key][0] != expected {
		t.Errorf("expected '%s', got '%s'", expected, params[key][0])
	}
}
func MockServer(t *testing.T) (ts *httptest.Server) {
	token := "aaaa-bbbb-cccc"
	called := 0
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		// check path
		if r.URL.EscapedPath() != "/identity/oauth/token" {
			t.Errorf("Expected path to be /identity/oauth/token, got %s", r.URL.EscapedPath())
		}

		// check query params
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			t.Errorf("Error parsing query params: %v", err)
		}
		checkParam(t, params, "client_id", clientID)
		checkParam(t, params, "client_secret", clientSecret)
		checkParam(t, params, "grant_type", "client_credentials")

		// check method
		if r.Method != "GET" {
			t.Errorf("Expected 'GET' request, got '%s'", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
	}))
	return
}
func NewTestConfig(t *testing.T, mockServer *httptest.Server) marketo.Config {
	return marketo.Config{
		ID:          clientID,
		URL:         mockServer.URL,
		Secret:      clientSecret,
		ClinicRole:  "clinic",
		PatientRole: "user",
		Timeout:     15000000000,
	}
}

func NewTestManagerWithClientMock(t *testing.T) marketo.Manager {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	x := MockServer(t)
	defer x.Close()
	config := NewTestConfig(t, x)
	manager, err := marketo.NewManager(logger, config)
	if manager == nil {
		t.Fatal("NewManager did not return manager when success expected")
	}
	if err != nil {
		t.Fatalf("NewManager error unexpected: %s", err)
		log.Fatal(err)
	}
	return manager
}

type UserMock struct {
	id                  int
	EmailInvocations    int
	EmailStub           func() string
	EmailOutputs        []string
	IsClinicInvocations int
	IsClinicStub        func() bool
	IsClinicOutputs     []bool
}

func NewUserMock() *UserMock {
	return &UserMock{id: rand.Int()}
}

func (u *UserMock) Email() string {
	u.EmailInvocations++
	if u.EmailStub != nil {
		return u.EmailStub()
	}
	if len(u.EmailOutputs) == 0 {
		panic(fmt.Sprintf("Unexpected invocation of Email on UserMock: %#v", u))
	}
	output := u.EmailOutputs[0]
	u.EmailOutputs = u.EmailOutputs[1:]
	return output
}

func (u *UserMock) IsClinic() bool {
	u.IsClinicInvocations++
	if u.IsClinicStub != nil {
		return u.IsClinicStub()
	}
	if len(u.IsClinicOutputs) == 0 {
		panic(fmt.Sprintf("Unexpected invocation of IsClinic on UserMock: %#v", u))
	}
	output := u.IsClinicOutputs[0]
	u.IsClinicOutputs = u.IsClinicOutputs[1:]
	return output
}

func (u *UserMock) AllOutputsConsumed() bool {
	return len(u.EmailOutputs) == 0 &&
		len(u.IsClinicOutputs) == 0
}
