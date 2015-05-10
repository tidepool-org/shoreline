package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		NewOAuthStorage(&mongo.Config{ConnectionString: "mongodb://localhost/oauth_test"}),
		shoreline.NewMock(user_secert_token),
		clients.NewGatekeeperMock(),
	)
)

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

	mockPerms := clients.NewGatekeeperMock()

	api := Api{permsApi: mockPerms}

	done := api.applyPermissons("123", "456", "view,upload")

	if done == false {
		t.Fatal("applyPermissons should have returned true on success")
	}
}

func Test_authorize(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	w := httptest.NewRecorder()
	api.authorize(w, r)

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

func Test_token(t *testing.T) {
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
	/*r, _ := http.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	api.info(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected [%v] and got [%v]", http.StatusOK, w.Code)
	}

	output := make(map[string]interface{})
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not decode output json: %s", err)
	}

	if output["error"] != nil {
		t.Fatalf("We don't expect an error details: %v", output["error"])
	}*/
}
