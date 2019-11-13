package marketo

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/SpeakData/minimarketo"
)

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

func TestNewClientSuccess(t *testing.T) {
	token := "aaaa-bbbb-cccc"
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	// check token
	tokenInfo := client.GetTokenInfo()
	if tokenInfo.Token != token {
		t.Errorf("Expected %s to equal %s", token, tokenInfo.Token)
	}
	if tokenInfo.Expires.IsZero() {
		t.Errorf("Expires field missing")
	}

	if called != 1 {
		t.Errorf("Expected only one call: %d", called)
	}
}

func TestNewClientError(t *testing.T) {
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		if r.Method != "GET" {
			t.Errorf("Expected 'GET' request, got '%s'", r.Method)
		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(authResponseError))
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}

	_, err := minimarketo.NewClient(config)
	if err != nil {
		expectedError := fmt.Sprintf("Authentication error: 401 %s", authResponseError)
		if err.Error() != expectedError {
			t.Errorf("Expected response:\n%s\n%s", expectedError, err)
		}

		if called != 1 {
			t.Errorf("Expected only one call: %d", called)
		}
		return
	}
	t.Error("Expectation not met")
}

func TestRefreshToken(t *testing.T) {
	tokens := []string{"aaaa-bbbb-cccc", "dddd-eeee-ffff"}
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		w.Write([]byte(fmt.Sprintf(authResponseSuccess, tokens[called])))
		called++
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	// check token
	tokenInfo := client.GetTokenInfo()
	if tokenInfo.Token != tokens[0] {
		t.Errorf("Expected %s to equal %s", tokens[0], tokenInfo.Token)
	}

	// refresh token
	authToken, err := client.RefreshToken()
	if err != nil {
		t.Error(err)
	}

	if authToken.AccessToken != tokens[1] {
		t.Errorf("Expected %s to equal %s", tokens[1], authToken.AccessToken)
	}
	if authToken.ExpiresIn != 3599 {
		t.Errorf("Expected 3599 to equal %d", authToken.ExpiresIn)
	}
	if authToken.TokenType != "bearer" {
		t.Errorf("Expected 'bearer' to equal %s", authToken.TokenType)
	}
	if authToken.Scope != "tester@example.com" {
		t.Errorf("Expected 'tester@example.com' to equal %s", authToken.Scope)
	}

	if called != 2 {
		t.Errorf("Expected only two calls: %d", called)
	}

	// check token again
	tokenInfo = client.GetTokenInfo()
	if tokenInfo.Token != tokens[1] {
		t.Errorf("Expected %s to equal %s", tokens[1], tokenInfo.Token)
	}
}

const (
	getResponseSuccess = `{
		"requestId":"1000",
		"result":[{"id":12345,"email":"tester@example.com"}],
		"success":true
	}`
	findLeadPath        = "/rest/v1/leads.json?filterType=email&fields=email,id&filterValues=tester@example.com"
	invalidFindLeadPath = "/rest/v1leads.json?filterType=email&fields=email,id&filterValues=tester@example.com"
)

func TestGetErrorWith500(t *testing.T) {
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if called == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
		}
		called++
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	_, err = client.Get(findLeadPath)
	if err != nil {
		if called != 2 {
			t.Errorf("Expected only two calls: %d", called)
		}
		expectedError := "Unexpected status code[500] with body[Internal server error]"
		if err.Error() != expectedError {
			t.Errorf("Expected %s, got %s", expectedError, err)
		}
		return
	}
	t.Error("Expectation not met")
}

func TestGetErrorWithNoBody(t *testing.T) {
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

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
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

func TestGetSuccess(t *testing.T) {
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

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	response, err := client.Get(findLeadPath)
	if err != nil {
		t.Error(err)
	}

	if !response.Success {
		t.Errorf("Expected true, got: %t", response.Success)
	}
	var leads []LeadResult
	err = json.Unmarshal(response.Result, &leads)
	if err != nil {
		t.Error(err)
	}

	if len(leads) != 1 {
		t.Errorf("Expected one lead, got: %d", len(leads))
	}

	if called != 2 {
		t.Errorf("Expected only two calls: %d", called)
	}
}

func TestGetSuccessWithSoonExpiringToken(t *testing.T) {
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if called == 0 {
			w.Write([]byte(fmt.Sprintf(authResponseExpiringSuccess, token)))
		} else if called == 1 {
			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		} else {
			// 3rd call
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

			if called == 1 {
				w.Write([]byte(tokenExpiredResponse))
			} else {
				w.Write([]byte(getResponseSuccess))
			}
		}
		called++
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	fmt.Println("Sleeping for 2 seconds...")
	time.Sleep(2 * time.Second)

	response, err := client.Get(findLeadPath)
	if err != nil {
		t.Error(err)
	}
	if !response.Success {
		t.Errorf("Expected true, got: %t", response.Success)
	}
	var leads []LeadResult
	if err = json.Unmarshal(response.Result, &leads); err != nil {
		t.Error(err)
	}
	if len(leads) != 1 {
		t.Errorf("Expected one lead, got: %d", len(leads))
	}

	if called != 3 {
		t.Errorf("Expected 3 calls: %d", called)
	}
}

func TestGetSuccessWithExpiringToken(t *testing.T) {
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if called == 0 || called == 2 {
			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		} else {
			// 2nd and 4th call
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

			if called == 1 {
				w.Write([]byte(tokenExpiredResponse))
			} else {
				w.Write([]byte(getResponseSuccess))
			}
		}
		called++
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	response, err := client.Get(findLeadPath)
	if err != nil {
		t.Error(err)
	}
	if !response.Success {
		t.Errorf("Expected true, got: %t", response.Success)
	}
	var leads []LeadResult
	if err = json.Unmarshal(response.Result, &leads); err != nil {
		t.Error(err)
	}
	if len(leads) != 1 {
		t.Errorf("Expected one lead, got: %d", len(leads))
	}

	if called != 4 {
		t.Errorf("Expected 4 calls: %d", called)
	}
}

func TestGetSuccessWithInvalidToken(t *testing.T) {
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if called == 0 || called == 2 {
			// 1st and 3rd call to auth
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

			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		} else {
			// 2nd and 4th call
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

			if called == 1 {
				w.Write([]byte(invalidTokenResponse))
			} else {
				w.Write([]byte(getResponseSuccess))
			}
		}
		// check method
		if r.Method != "GET" {
			t.Errorf("Expected 'GET' request, got '%s'", r.Method)
		}
		called++
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	response, err := client.Get(findLeadPath)
	if err != nil {
		t.Error(err)
	}
	if !response.Success {
		t.Errorf("Expected true, got: %t", response.Success)
	}
	var leads []LeadResult
	if err = json.Unmarshal(response.Result, &leads); err != nil {
		t.Error(err)
	}
	if len(leads) != 1 {
		t.Errorf("Expected one lead, got: %d", len(leads))
	}

	if called != 4 {
		t.Errorf("Expected 4 calls: %d", called)
	}
}

const (
	removeFromListResponseSuccess = `{
		"requestId":"1000",
		"result":[{"id":12345,"status":"removed"}],
		"success":true
	}`
)

type RemoveFromListRequest struct {
	Input []struct {
		ID int `json:"id"`
	} `json:"input"`
}

func TestDeleteSuccess(t *testing.T) {
	listID := 1000
	inputID := 3
	path := fmt.Sprintf("/rest/v1/lists/%d/leads.json", listID)
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if called == 0 {
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}

			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		} else {
			// check path
			if r.URL.EscapedPath() != path {
				t.Errorf("Expected path to be %s, got %s", path, r.URL.EscapedPath())
			}

			// check method
			if r.Method != "DELETE" {
				t.Errorf("Expected 'DELETE' request, got '%s'", r.Method)
			}

			// check body
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			var requestBody RemoveFromListRequest
			if err := json.Unmarshal(body, &requestBody); err != nil {
				t.Error(err)
			}
			if len(requestBody.Input) != 1 {
				t.Errorf("Expected one id, got %d", len(requestBody.Input))
			}
			if requestBody.Input[0].ID != inputID {
				t.Errorf("Expected id %d, got %d", inputID, requestBody.Input[0].ID)
			}
			w.Write([]byte(removeFromListResponseSuccess))
		}
		called++
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	response, err := client.Delete(path, json.RawMessage(fmt.Sprintf(`{"input": [{"id": %d}]}`, inputID)))
	if err != nil {
		t.Error(err)
	}

	if !response.Success {
		t.Errorf("Expected true, got: %t", response.Success)
	}
	var results []minimarketo.RecordResult
	err = json.Unmarshal(response.Result, &results)
	if err != nil {
		t.Error(err)
	}
	if len(results) != 1 {
		t.Errorf("Expected one lead, got: %d", len(results))
	}

	if called != 2 {
		t.Errorf("Expected only two calls: %d", called)
	}
}

const (
	createLeadResponseSuccess = `{
		"requestId":"1000",
		"result":[{"id":12345,"status":"created"}],
		"success":true
	}`
	createLeadRequest = `{
		"action":"createOnly",
		"lookupField":"email",
		"input": [{"email": "%s", "firstName": "%s", "lastName": "%s", "userType": "%s"}]
	}`
)

type CreateLeadRequest struct {
	Action      string `json:"action"`
	LookupField string `json:"lookupField"`
	Input       []struct {
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		UserType  string `json:"userType"`
	} `json:"input"`
}

func TestPostSuccess(t *testing.T) {
	path := "/rest/v1/leads.json"
	email := "tester@example.com"
	firstName := "John"
	lastName := "Doe"
	userType := "clinician"
	called := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		if called == 0 {
			// check method
			if r.Method != "GET" {
				t.Errorf("Expected 'GET' request, got '%s'", r.Method)
			}

			w.Write([]byte(fmt.Sprintf(authResponseSuccess, token)))
		} else {
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
			if requestBody.Input[0].Email != email {
				t.Errorf("Expected %s, got %s", email, requestBody.Input[0].Email)
			}
			if requestBody.Input[0].FirstName != firstName {
				t.Errorf("Expected %s, got %s", email, requestBody.Input[0].FirstName)
			}
			if requestBody.Input[0].LastName != lastName {
				t.Errorf("Expected %s, got %s", email, requestBody.Input[0].LastName)
			}
			w.Write([]byte(createLeadResponseSuccess))
		}
		called++
	}))
	defer ts.Close()

	// New Marketo Client
	config := minimarketo.ClientConfig{
		ID:       clientID,
		Secret:   clientSecret,
		Endpoint: ts.URL,
		Debug:    true,
	}
	client, err := minimarketo.NewClient(config)
	if err != nil {
		t.Error(err)
	}

	response, err := client.Post(path, json.RawMessage(fmt.Sprintf(createLeadRequest, email, firstName, lastName, userType)))
	if err != nil {
		t.Error(err)
	}

	if !response.Success {
		t.Errorf("Expected true, got: %t", response.Success)
	}
	var results []minimarketo.RecordResult
	err = json.Unmarshal(response.Result, &results)
	if err != nil {
		t.Error(err)
	}
	if len(results) != 1 {
		t.Errorf("Expected one lead, got: %d", len(results))
	}

	if called != 2 {
		t.Errorf("Expected only two calls: %d", called)
	}
}
