package mailchimp_test

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mdblp/shoreline/user/mailchimp"
)

func Test_List_Validate_Missing(t *testing.T) {
	var list *mailchimp.List
	err := list.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: list is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_List_Validate_ID_Missing(t *testing.T) {
	list := &mailchimp.List{
		Interests: map[string]bool{"one": true, "two": true, "three": true},
	}
	err := list.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: id is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_List_Validate_Interest_ID_Missing(t *testing.T) {
	list := &mailchimp.List{
		ID:        "test-list-id",
		Interests: map[string]bool{"one": true, "": true, "three": true},
	}
	err := list.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: interest id is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_List_Validate_Success(t *testing.T) {
	list := &mailchimp.List{
		ID:        "test-list-id",
		Interests: map[string]bool{"one": true, "two": true, "three": true},
	}
	err := list.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_List_Validate_Success_InterestsMissing(t *testing.T) {
	list := &mailchimp.List{
		ID: "test-list-id",
	}
	err := list.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_List_Validate_Success_InterestsEmpty(t *testing.T) {
	list := &mailchimp.List{
		ID:        "test-list-id",
		Interests: map[string]bool{},
	}
	err := list.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Lists_Validate_Missing(t *testing.T) {
	var lists mailchimp.Lists
	err := lists.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: lists are missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Lists_Validate_List_Missing(t *testing.T) {
	lists := mailchimp.Lists{
		nil,
	}
	err := lists.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: list is not valid; mailchimp: list is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Lists_Validate_List_NotValid(t *testing.T) {
	lists := mailchimp.Lists{
		&mailchimp.List{},
	}
	err := lists.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: list is not valid; mailchimp: id is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Lists_Validate_Success(t *testing.T) {
	lists := mailchimp.Lists{
		&mailchimp.List{
			ID: "clinic-list-id",
		},
		&mailchimp.List{
			ID:        "personal-list-id",
			Interests: map[string]bool{"one": true, "two": true, "three": true},
		},
	}
	err := lists.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Lists_Validate_Success_ListsEmpty(t *testing.T) {
	lists := mailchimp.Lists{}
	err := lists.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_Missing(t *testing.T) {
	var config *mailchimp.Config
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: config is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_URL_Missing(t *testing.T) {
	config := NewTestConfig(t)
	config.URL = ""
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: url is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_APIKey_Missing(t *testing.T) {
	config := NewTestConfig(t)
	config.APIKey = ""
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: api key is missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_ClinicLists_Missing(t *testing.T) {
	config := NewTestConfig(t)
	config.ClinicLists = nil
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: clinic lists are not valid; mailchimp: lists are missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_PersonalLists_Missing(t *testing.T) {
	config := NewTestConfig(t)
	config.PersonalLists = nil
	err := config.Validate()
	if err == nil {
		t.Fatal("Validate returned successfully when error expected")
	}
	if err.Error() != "mailchimp: personal lists are not valid; mailchimp: lists are missing" {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_Config_Validate_Success(t *testing.T) {
	config := NewTestConfig(t)
	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate error unexpected: %s", err)
	}
}

func Test_NewManager_Logger_Missing(t *testing.T) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	config := NewTestConfig(t)
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
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	config := NewTestConfig(t)
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
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
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
	if err.Error() != "mailchimp: config is not valid; mailchimp: config is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Config_Invalid(t *testing.T) {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	config := NewTestConfig(t)
	config.URL = ""
	manager, err := mailchimp.NewManager(logger, client, config)
	if manager != nil {
		t.Fatal("NewManager returned manager when error expected")
	}
	if err == nil {
		t.Fatal("NewManager returned successfully when error expected")
	}
	if err.Error() != "mailchimp: config is not valid; mailchimp: url is missing" {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_NewManager_Success(t *testing.T) {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	config := NewTestConfig(t)
	manager, err := mailchimp.NewManager(logger, client, config)
	if manager == nil {
		t.Fatal("NewManager did not return manager when success expected")
	}
	if err != nil {
		t.Fatalf("NewManager error unexpected: %s", err)
	}
}

func Test_CreateListMembershipForUser_User_Missing(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	manager.CreateListMembershipForUser(nil)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_User_Email_Missing(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "" }
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_User_Email_Tidepool_Io(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.io" }
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_User_Email_Tidepool_Org(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.org" }
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
}

func Test_CreateListMembershipForUser_Failure_Get_Do(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "one@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{{nil, errors.New("test failure")}}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Failure_Get_StatusCode(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "two@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusForbidden}, nil}}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Failure_Get_DecodeJSON(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "three@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{{&http.Response{Body: ioutil.NopCloser(strings.NewReader("{"))}, nil}}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Failure_Put_Do(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "four@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{nil, errors.New("test failure")},
	}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Failure_Put_StatusCode(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "five@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusForbidden}, nil},
	}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Clinic_Success(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "SIX@SAMPLE.COM" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
	}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 2 {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "clinic-list-id", newUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[1], "clinic-list-id", newUserMock.Email(), `{"email_address":"six@sample.com","status_if_new":"subscribed","interests":{"zero":true}}`)
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Clinic_Success_Existing(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "seven@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("{}"))}, nil}}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "clinic-list-id", newUserMock.Email())
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Personal_Success(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "eight@sample.com" }
	newUserMock.IsClinicStub = func() bool { return false }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
	}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 4 {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "personal-list-id", newUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[1], "personal-list-id", newUserMock.Email(), `{"email_address":"eight@sample.com","status_if_new":"subscribed","interests":{"one":true,"three":true,"two":true}}`)
	AssertGetListMember(t, clientMock.DoInputs[2], "alternate-personal-list-id", newUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[3], "alternate-personal-list-id", newUserMock.Email(), `{"email_address":"eight@sample.com","status_if_new":"subscribed"}`)
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_CreateListMembershipForUser_Personal_Success_Existing(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "nine@sample.com" }
	newUserMock.IsClinicStub = func() bool { return false }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("{}"))}, nil},
		{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("{}"))}, nil},
	}
	manager.CreateListMembershipForUser(newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 2 {
		t.Fatalf("CreateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "personal-list-id", newUserMock.Email())
	AssertGetListMember(t, clientMock.DoInputs[1], "alternate-personal-list-id", newUserMock.Email())
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_OldUser_Missing(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	newUserMock := NewUserMock()
	manager.UpdateListMembershipForUser(nil, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Missing(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	manager.UpdateListMembershipForUser(oldUserMock, nil)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Match_Personal(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "ten@sample.com" }
	oldUserMock.IsClinicStub = func() bool { return false }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "ten@sample.com" }
	newUserMock.IsClinicStub = func() bool { return false }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Match_Clinic(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "eleven@sample.com" }
	oldUserMock.IsClinicStub = func() bool { return true }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "eleven@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Email_Missing(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twelve@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "" }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Email_Tidepool_Io(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twelve@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.io" }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_NewUser_Email_Tidepool_Org(t *testing.T) {
	manager, _ := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twelve@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "test@tidepool.org" }
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
}

func Test_UpdateListMembershipForUser_Failure_Put_Do(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "thirteen@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "fourteen@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{nil, errors.New("test failure")},
	}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_Failure_Put_StatusCode(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "fifteen@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "sixteen@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusForbidden}, nil},
	}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_Clinic_Success_New(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "seventeen@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "eighteen@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
	}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 2 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "clinic-list-id", oldUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[1], "clinic-list-id", oldUserMock.Email(), `{"email_address":"eighteen@sample.com","status_if_new":"subscribed","interests":{"zero":true}}`)
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_Clinic_Success_Existing_SameEmail(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "nineteen@sample.com" }
	oldUserMock.IsClinicStub = func() bool { return false }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "nineteen@sample.com" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("{}"))}, nil}}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 1 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "clinic-list-id", oldUserMock.Email())
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_Clinic_Success_Existing_DifferentEmail(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "TWENTY@SAMPLE.COM" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "TWENTYONE@SAMPLE.COM" }
	newUserMock.IsClinicStub = func() bool { return true }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader(`{"email_address":"twenty@sample.com","interests":{"alpha":true,"beta":true}}`))}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
	}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 2 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "clinic-list-id", oldUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[1], "clinic-list-id", oldUserMock.Email(), `{"email_address":"twentyone@sample.com","interests":{"alpha":true,"beta":true}}`)
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_Personal_Success_New(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twentytwo@sample.com" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "twentythree@sample.com" }
	newUserMock.IsClinicStub = func() bool { return false }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
		{&http.Response{StatusCode: http.StatusNotFound}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
	}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 4 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "personal-list-id", oldUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[1], "personal-list-id", oldUserMock.Email(), `{"email_address":"twentythree@sample.com","status_if_new":"subscribed","interests":{"one":true,"three":true,"two":true}}`)
	AssertGetListMember(t, clientMock.DoInputs[2], "alternate-personal-list-id", oldUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[3], "alternate-personal-list-id", oldUserMock.Email(), `{"email_address":"twentythree@sample.com","status_if_new":"subscribed"}`)
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_Personal_Success_Existing_SameEmail(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "twentyfour@sample.com" }
	oldUserMock.IsClinicStub = func() bool { return true }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "twentyfour@sample.com" }
	newUserMock.IsClinicStub = func() bool { return false }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("{}"))}, nil},
		{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader("{}"))}, nil},
	}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 2 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "personal-list-id", oldUserMock.Email())
	AssertGetListMember(t, clientMock.DoInputs[1], "alternate-personal-list-id", oldUserMock.Email())
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func Test_UpdateListMembershipForUser_Personal_Success_Existing_DifferentEmail(t *testing.T) {
	manager, clientMock := NewTestManagerWithClientMock(t)
	oldUserMock := NewUserMock()
	oldUserMock.EmailStub = func() string { return "TWENTYFIVE@SAMPLE.COM" }
	newUserMock := NewUserMock()
	newUserMock.EmailStub = func() string { return "TWENTYSIX@SAMPLE.COM" }
	newUserMock.IsClinicStub = func() bool { return false }
	clientMock.DoOutputs = []DoOutput{
		{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader(`{"email_address":"twentyfive@sample.com"}`))}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
		{&http.Response{StatusCode: http.StatusOK, Body: ioutil.NopCloser(strings.NewReader(`{"email_address":"twentyfive@sample.com","interests":{"alpha":true,"beta":true}}`))}, nil},
		{&http.Response{StatusCode: http.StatusOK}, nil},
	}
	manager.UpdateListMembershipForUser(oldUserMock, newUserMock)
	manager.WaitGroup().Wait()
	if length := len(clientMock.DoInputs); length != 4 {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do an unexpected number of times: %d", length)
	}
	AssertGetListMember(t, clientMock.DoInputs[0], "personal-list-id", oldUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[1], "personal-list-id", oldUserMock.Email(), `{"email_address":"twentysix@sample.com"}`)
	AssertGetListMember(t, clientMock.DoInputs[2], "alternate-personal-list-id", oldUserMock.Email())
	AssertPutListMember(t, clientMock.DoInputs[3], "alternate-personal-list-id", oldUserMock.Email(), `{"email_address":"twentysix@sample.com","interests":{"alpha":true,"beta":true}}`)
	if !clientMock.AllOutputsConsumed() {
		t.Fatal("Not all outputs consumed for clientMock")
	}
}

func AssertGetListMember(t *testing.T, request *http.Request, listID string, email string) {
	if method := request.Method; method != "GET" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != fmt.Sprintf("https://mailchimp.com/lists/%s/members/%s", listID, AssertEmailHash(email)) {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body != nil {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do with body")
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`UpdateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
}

func AssertPutListMember(t *testing.T, request *http.Request, listID string, email string, bodyString string) {
	if method := request.Method; method != "PUT" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected method: %s", method)
	}
	if url := request.URL.String(); url != fmt.Sprintf("https://mailchimp.com/lists/%s/members/%s", listID, AssertEmailHash(email)) {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected URL: %s", url)
	}
	if body := request.Body; body == nil {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do with no body")
	} else if bodyBytes, err := ioutil.ReadAll(body); err != nil {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unreadable body: %s", err)
	} else if bodyBytesString := string(bodyBytes); bodyBytesString != bodyString {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected body: %s", bodyBytesString)
	}
	if username, password, ok := request.BasicAuth(); !ok {
		t.Fatal("UpdateListMembershipForUser invoked Client.Do without expected Basic Auth")
	} else if username != "tidepool-platform" || password != "test-api-key" {
		t.Fatalf(`UpdateListMembershipForUser invoked Client.Do with unexpected Basic Auth: username="%s", password="%s"`, username, password)
	}
	if header := request.Header.Get("Content-Type"); header != "application/json" {
		t.Fatalf("UpdateListMembershipForUser invoked Client.Do with unexpected Content-Type header: %s", header)
	}
}

func AssertEmailHash(email string) string {
	md5Sum := md5.Sum([]byte(strings.ToLower(email)))
	return hex.EncodeToString(md5Sum[:])
}

func NewTestConfig(t *testing.T) *mailchimp.Config {
	return &mailchimp.Config{
		URL:    "https://mailchimp.com",
		APIKey: "test-api-key",
		ClinicLists: mailchimp.Lists{
			&mailchimp.List{
				ID:        "clinic-list-id",
				Interests: map[string]bool{"zero": true},
			},
		},
		PersonalLists: mailchimp.Lists{
			&mailchimp.List{
				ID:        "personal-list-id",
				Interests: map[string]bool{"one": true, "two": true, "three": true},
			},
			&mailchimp.List{
				ID: "alternate-personal-list-id",
			},
		},
	}
}

func NewTestManagerWithClientMock(t *testing.T) (mailchimp.Manager, *ClientMock) {
	logger := log.New(ioutil.Discard, "", log.LstdFlags)
	clientMock := NewClientMock()
	config := NewTestConfig(t)
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
	DoStub        func(request *http.Request) (*http.Response, error)
	DoOutputs     []DoOutput
}

func NewClientMock() *ClientMock {
	return &ClientMock{id: rand.Int()}
}

func (c *ClientMock) Do(request *http.Request) (*http.Response, error) {
	c.DoInvocations++
	c.DoInputs = append(c.DoInputs, request)
	if c.DoStub != nil {
		return c.DoStub(request)
	}
	if len(c.DoOutputs) == 0 {
		panic(fmt.Sprintf("Unexpected invocation of Do on ClientMock: %#v", c))
	}
	output := c.DoOutputs[0]
	c.DoOutputs = c.DoOutputs[1:]
	return output.Out1, output.Out2
}

func (c *ClientMock) AllOutputsConsumed() bool {
	return len(c.DoOutputs) == 0
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
