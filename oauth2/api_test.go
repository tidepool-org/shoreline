package oauth2

import (
	"net/url"
	"testing"

	"github.com/tidepool-org/go-common/clients"
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

	mockPerms := clients.NewGatekeeperMock(nil, nil)

	api := Api{permsApi: mockPerms}

	done := api.applyPermissons("123", "456", "view,upload")

	if done == false {
		t.Fatal("applyPermissons should have returned true on success")
	}

}
