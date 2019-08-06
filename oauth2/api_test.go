package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/go-common/clients/shoreline"
)

const (
	user_secert_token = "its no secret"
)

var (
	api = InitApi(
		ApiConfig{ExpireDays: 20},
		NewOAuthStorage(&mongo.Config{ConnectionString: "mongodb://127.0.0.1/user_test"}),
		shoreline.NewMock(user_secert_token),
		clients.NewGatekeeperMock(nil, nil),
	)
)

//using the attached mongo session setup and required data for testing.
//NOTE: we just blow away the test data for each test
func setupClientForTest() {
	cpy := api.storage.session.Copy()
	defer cpy.Close()
	//just drop and don't worry about any errors
	cpy.DB("").DropDatabase()
	//TODO: we are reusing `a_client` from the oauthStore_test.go tests. We need to do this in a nicer way
	api.storage.SetClient(a_client.GetId(), a_client)
}

func Test_signupFormValid(t *testing.T) {

	formData := make(url.Values)
	formData["usr_name"] = []string{"other"}
	formData["password"] = []string{"stuff"}
	formData["password_confirm"] = []string{"stuff"}
	formData["uri"] = []string{"and"}
	formData["email"] = []string{"some@more.org"}

	_, valid := signupFormValid(formData)

	if valid == false {
		t.Fatalf("form %v should be valid", formData)
	}
}

func Test_signupFormValid_false(t *testing.T) {

	formData := make(url.Values)
	formData["usr_name"] = []string{"other"}
	formData["password"] = []string{""}
	formData["uri"] = []string{"and"}
	formData["email"] = []string{"some@more.org"}

	_, valid := signupFormValid(formData)

	if valid {
		t.Fatalf("form %v should NOT be valid", formData)
	}
}

func Test_applyPermissons(t *testing.T) {

	mockPerms := clients.NewGatekeeperMock(nil, nil)

	api := Api{permsApi: mockPerms}

	done := api.applyPermissons("123", "456", "view,upload")

	if done == false {
		t.Fatal("applyPermissons should have returned true on success")
	}
}

func Test_POST_authorize(t *testing.T) {
	//TODO: pre-reqs still need to be set
	r, _ := http.NewRequest("POST", fmt.Sprintf("/?response_type=code&client_id=%s&redirect_uri=%s", a_client.GetId(), a_client.GetRedirectUri()), nil)
	w := httptest.NewRecorder()
	api.authorize(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusOK, w.Code)
	}

	t.Logf("output from Test_POST_authorize %s", string(w.Body.Bytes()[:]))

	/*if output["error"] != nil {
		t.Fatalf("We don't expect an error details: %v", output["error"])
	}*/
}

func Test_GET_authorize(t *testing.T) {

	setupClientForTest()

	r, _ := http.NewRequest("GET", fmt.Sprintf("/?response_type=code&client_id=%s&redirect_uri=%s", a_client.GetId(), a_client.GetRedirectUri()), nil)
	w := httptest.NewRecorder()
	api.authorize(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusOK, w.Code)
	}

	authPage := string(w.Body.Bytes()[:])

	//What we are looking for
	expectedAuthFormParts := []string{
		"/auth/oauth2/authorize?response_type=code&client_id=1234&state=&scope=&redirect_uri=http%3A%2F%2Flocalhost%3A14000",
		"method=\"POST\"",                                                        //it should be a POST
		scopeView.grantMsg,                                                       //should show user would be granting view permissons
		scopeUpload.grantMsg,                                                     //should show user would be granting upload permissons
		"<input type=\"text\" name=\"login\" placeholder=\"Email\" />",           //should ask for users email address
		"<input type=\"password\" name=\"password\" placeholder=\"Password\" />", //should ask for users password
		"<input type=\"submit\" value=\"Grant access to Tidepool\"/>",            //should allow them to submit
	}

	for i := range expectedAuthFormParts {
		if strings.Contains(authPage, expectedAuthFormParts[i]) == false {
			t.Logf("expected [%s]", authPage)
			t.Logf("to contain [%s]", expectedAuthFormParts[i])
			t.Fatal("Test_GET_authorize didn't render the expected authorize form")
		}
	}
}

func Test_token(t *testing.T) {
	//TODO: pre-reqs still need to be set
	r, _ := http.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	api.token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusOK, w.Code)
	}

	output := make(map[string]interface{})
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	/*if output["error"] != nil {
		t.Fatalf("We don't expect an error details: %v", output["error"])
	}*/
}

func Test_info(t *testing.T) {
	//TODO
}
