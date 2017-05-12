package mailchimp_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"testing"
	"time"

	"../mailchimp"
)

func Test_Config_IsValid_URL_Missing(t *testing.T) {
	config := &mailchimp.Config{
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
		ClinicListID:   "clinic-list-id",
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: url is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_IsValid_APIKey_Missing(t *testing.T) {
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		PersonalListID: "personal-list-id",
		ClinicListID:   "clinic-list-id",
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: api key is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_IsValid_PersonalListID_Missing(t *testing.T) {
	config := &mailchimp.Config{
		URL:          "https://mailchimp.com",
		APIKey:       "test-api-key",
		ClinicListID: "clinic-list-id",
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: personal list id is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_IsValid_ClinicListID_Missing(t *testing.T) {
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: clinic list id is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_IsValid_Successful(t *testing.T) {
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
		ClinicListID:   "clinic-list-id",
	}
	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_NewManager_Logger_Missing(t *testing.T) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
		ClinicListID:   "clinic-list-id",
	}
	manager, err := mailchimp.NewManager(nil, client, config)
	if manager != nil {
		t.Fatal("NewManager returned manager when error expected")
	}
	if err == nil {
		t.Fatal("NewManager returned successfully when error expected")
	}
	if err.Error() != "mailchimp: logger is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Client_Missing(t *testing.T) {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
		ClinicListID:   "clinic-list-id",
	}
	manager, err := mailchimp.NewManager(logger, nil, config)
	if manager != nil {
		t.Fatal("NewManager returned manager when error expected")
	}
	if err == nil {
		t.Fatal("NewManager returned successfully when error expected")
	}
	if err.Error() != "mailchimp: client is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Config_Missing(t *testing.T) {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	manager, err := mailchimp.NewManager(logger, client, nil)
	if manager != nil {
		t.Fatal("NewManager returned manager when error expected")
	}
	if err == nil {
		t.Fatal("NewManager returned successfully when error expected")
	}
	if err.Error() != "mailchimp: config is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Config_Invalid(t *testing.T) {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
	}
	manager, err := mailchimp.NewManager(logger, client, config)
	if manager != nil {
		t.Fatal("NewManager returned manager when error expected")
	}
	if err == nil {
		t.Fatal("NewManager returned successfully when error expected")
	}
	if err.Error() != "mailchimp: config is not valid; mailchimp: clinic list id is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Successful(t *testing.T) {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
		ClinicListID:   "clinic-list-id",
	}
	manager, err := mailchimp.NewManager(logger, client, config)
	if manager == nil {
		t.Fatal("NewManager did not return manager when success expected")
	}
	if err != nil {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_CreateListMembershipForUser_User_Missing(t *testing.T) {
	manager, _ := NewManagerWithClientMock(t)
	manager.CreateListMembershipForUser(nil)
	time.Sleep(time.Second)
}

func Test_CreateListMembershipForUser_User_Email_Missing(t *testing.T) {
	manager, _ := NewManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{""}
	manager.CreateListMembershipForUser(newUserMock)
	time.Sleep(time.Second)
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
}

func Test_CreateListMembershipForUser_Failure_Do(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"one@sample.com", "one@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false}
	clientMock.DoOutputs = []DoOutput{{nil, errors.New("test failure")}}
	manager.CreateListMembershipForUser(newUserMock)
	time.Sleep(time.Second)
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
}

func Test_CreateListMembershipForUser_Failure_StatusCode(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"two@sample.com", "two@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusForbidden}, nil}}
	manager.CreateListMembershipForUser(newUserMock)
	time.Sleep(time.Second)
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
}

func Test_CreateListMembershipForUser_Personal_Success(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"three@sample.com", "three@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK}, nil}}
	manager.CreateListMembershipForUser(newUserMock)
	time.Sleep(time.Second)
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	request := clientMock.DoInputs[0]
	if method := request.Method; method != "PUT" {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != "https://mailchimp.com/lists/personal-list-id/members/e369244a2c208f05f3985de14530dda8" {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body == nil {
		t.Fatal("CreateListMembershipForUser invoked Client.Do with no body")
	} else if bodyBytes, err := ioutil.ReadAll(body); err != nil {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unreadable body: %s", err)
	} else if bodyString := string(bodyBytes); bodyString != `{"email_address":"three@sample.com","status_if_new":"subscribed"}` {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected body: %s", bodyString)
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("CreateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`CreateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
	if header := request.Header.Get("Content-Type"); header != "application/json" {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected Content-Type header: %s", header)
	}
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
}

func Test_CreateListMembershipForUser_Clinic_Success(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"four@sample.com", "four@sample.com"}
	newUserMock.IsClinicOutputs = []bool{true}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK}, nil}}
	manager.CreateListMembershipForUser(newUserMock)
	time.Sleep(time.Second)
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	request := clientMock.DoInputs[0]
	if method := request.Method; method != "PUT" {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != "https://mailchimp.com/lists/clinic-list-id/members/4be9e246893e38ad76a7c03274e945ee" {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body == nil {
		t.Fatal("CreateListMembershipForUser invoked Client.Do with no body")
	} else if bodyBytes, err := ioutil.ReadAll(body); err != nil {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unreadable body: %s", err)
	} else if bodyString := string(bodyBytes); bodyString != `{"email_address":"four@sample.com","status_if_new":"subscribed"}` {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected body: %s", bodyString)
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("CreateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`CreateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
	if header := request.Header.Get("Content-Type"); header != "application/json" {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do with unexpected Content-Type header: %s", header)
	}
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
}

func Test_UpdateListMembershipForUser_OldUser_Missing(t *testing.T) {
	manager, _ := NewManagerWithClientMock(t)
	newUserMock := NewUserMock()
	manager.UpdateListMembershipForUser(nil, newUserMock)
	time.Sleep(time.Second)
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
}

func Test_UpdateListMembershipForUser_NewUser_Missing(t *testing.T) {
	manager, _ := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	manager.UpdateListMembershipForUser(oldUserMock, nil)
	time.Sleep(time.Second)
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_NewUser_Match(t *testing.T) {
	manager, _ := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"five@sample.com"}
	oldUserMock.IsClinicOutputs = []bool{false}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"five@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_NewUser_Email_Missing(t *testing.T) {
	manager, _ := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"six@sample.com"}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"", ""}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_Failure_Do(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"seven@sample.com", "seven@sample.com", "seven@sample.com"}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"eight@sample.com", "eight@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false}
	clientMock.DoOutputs = []DoOutput{{nil, errors.New("test failure")}}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_Failure_StatusCode(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"nine@sample.com", "nine@sample.com", "nine@sample.com"}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"ten@sample.com", "ten@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusForbidden}, nil}}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_Personal_Success(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"eleven@sample.com", "eleven@sample.com", "eleven@sample.com"}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"twelve@sample.com", "twelve@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK}, nil}}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	request := clientMock.DoInputs[0]
	if method := request.Method; method != "PUT" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != "https://mailchimp.com/lists/personal-list-id/members/4130656d43b4a92dafd26e13a87030d6" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body == nil {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do with no body")
	} else if bodyBytes, err := ioutil.ReadAll(body); err != nil {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unreadable body: %s", err)
	} else if bodyString := string(bodyBytes); bodyString != `{"email_address":"twelve@sample.com","status_if_new":"subscribed"}` {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected body: %s", bodyString)
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`UpdateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
	if header := request.Header.Get("Content-Type"); header != "application/json" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected Content-Type header: %s", header)
	}
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_Clinic_Success(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"thirteen@sample.com", "thirteen@sample.com", "thirteen@sample.com"}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"fourteen@sample.com", "fourteen@sample.com"}
	newUserMock.IsClinicOutputs = []bool{true}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK}, nil}}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	request := clientMock.DoInputs[0]
	if method := request.Method; method != "PUT" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != "https://mailchimp.com/lists/clinic-list-id/members/62fdb2943249daa30f3bc820eb641067" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body == nil {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do with no body")
	} else if bodyBytes, err := ioutil.ReadAll(body); err != nil {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unreadable body: %s", err)
	} else if bodyString := string(bodyBytes); bodyString != `{"email_address":"fourteen@sample.com","status_if_new":"subscribed"}` {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected body: %s", bodyString)
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`UpdateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
	if header := request.Header.Get("Content-Type"); header != "application/json" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected Content-Type header: %s", header)
	}
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_Personal_To_Clinic_Success(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"fifteen@sample.com", "fifteen@sample.com", "fifteen@sample.com"}
	oldUserMock.IsClinicOutputs = []bool{false}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"fifteen@sample.com", "fifteen@sample.com"}
	newUserMock.IsClinicOutputs = []bool{true, true}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK}, nil}}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	request := clientMock.DoInputs[0]
	if method := request.Method; method != "PUT" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != "https://mailchimp.com/lists/clinic-list-id/members/1a4f775a8150208e502f18ad69bb1b7b" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body == nil {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do with no body")
	} else if bodyBytes, err := ioutil.ReadAll(body); err != nil {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unreadable body: %s", err)
	} else if bodyString := string(bodyBytes); bodyString != `{"email_address":"fifteen@sample.com","status_if_new":"subscribed"}` {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected body: %s", bodyString)
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`UpdateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
	if header := request.Header.Get("Content-Type"); header != "application/json" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected Content-Type header: %s", header)
	}
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func Test_UpdateListMembershipForUser_Clinic_To_Personal_Success(t *testing.T) {
	manager, clientMock := NewManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailOutputs = []string{"sixteen@sample.com", "sixteen@sample.com", "sixteen@sample.com"}
	oldUserMock.IsClinicOutputs = []bool{true}
	newUserMock := NewUserMock()
	newUserMock.EmailOutputs = []string{"sixteen@sample.com", "sixteen@sample.com"}
	newUserMock.IsClinicOutputs = []bool{false, false}
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK}, nil}}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	time.Sleep(time.Second)
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	request := clientMock.DoInputs[0]
	if method := request.Method; method != "PUT" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != "https://mailchimp.com/lists/personal-list-id/members/0545bb27c4733c45504482883c367ad9" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body == nil {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do with no body")
	} else if bodyBytes, err := ioutil.ReadAll(body); err != nil {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unreadable body: %s", err)
	} else if bodyString := string(bodyBytes); bodyString != `{"email_address":"sixteen@sample.com","status_if_new":"subscribed"}` {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected body: %s", bodyString)
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`UpdateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
	if header := request.Header.Get("Content-Type"); header != "application/json" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected Content-Type header: %s", header)
	}
	if !clientMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
	if !newUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for newUserMock")
	}
	if !oldUserMock.TestOutputsValid() {
		t.Fatal("Not all outputs consumed for oldUserMock")
	}
}

func NewManagerWithClientMock(t *testing.T) (mailchimp.Manager, *ClientMock) {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	clientMock := NewClientMock()
	config := &mailchimp.Config{
		URL:            "https://mailchimp.com",
		APIKey:         "test-api-key",
		PersonalListID: "personal-list-id",
		ClinicListID:   "clinic-list-id",
	}
	manager, err := mailchimp.NewManager(logger, clientMock, config)
	if manager == nil {
		t.Fatal("NewManager did not return manager when success expected")
	}
	if err != nil {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
	return manager, clientMock
}

type DoOutput struct {
	Out1 *http.Response
	Out2 error
}

type ClientMock struct {
	id            int
	DoInvocations int
	DoInputs      []*http.Request
	DoOutputs     []DoOutput
}

func NewClientMock() *ClientMock {
	return &ClientMock{id: rand.Int()}
}

func (c *ClientMock) Do(request *http.Request) (*http.Response, error) {
	if len(c.DoOutputs) == 0 {
		panic(fmt.Sprintf("Unexpected invocation of Do on ClientMock: %#v", c))
	}
	c.DoInvocations++
	c.DoInputs = append(c.DoInputs, request)
	output := c.DoOutputs[0]
	c.DoOutputs = c.DoOutputs[1:]
	return output.Out1, output.Out2
}

func (c *ClientMock) TestOutputsValid() bool {
	return len(c.DoOutputs) == 0
}

type UserMock struct {
	id                  int
	EmailInvocations    int
	EmailOutputs        []string
	IsClinicInvocations int
	IsClinicOutputs     []bool
}

func NewUserMock() *UserMock {
	return &UserMock{id: rand.Int()}
}

func (u *UserMock) Email() string {
	if len(u.EmailOutputs) == 0 {
		panic(fmt.Sprintf("Unexpected invocation of Email on UserMock: %#v", u))
	}
	u.EmailInvocations++
	output := u.EmailOutputs[0]
	u.EmailOutputs = u.EmailOutputs[1:]
	return output
}

func (u *UserMock) IsClinic() bool {
	if len(u.IsClinicOutputs) == 0 {
		panic(fmt.Sprintf("Unexpected invocation of IsClinic on UserMock: %#v", u))
	}
	u.IsClinicInvocations++
	output := u.IsClinicOutputs[0]
	u.IsClinicOutputs = u.IsClinicOutputs[1:]
	return output
}

func (u *UserMock) TestOutputsValid() bool {
	return len(u.EmailOutputs) == 0 &&
		len(u.IsClinicOutputs) == 0
}
