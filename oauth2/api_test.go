package oauth2

import (
	"net/url"
	"strings"
	"testing"

	"github.com/tidepool-org/go-common/clients"
)

func Test_selectedScopes(t *testing.T) {

	formData := make(url.Values)
	formData[scopeView.name] = []string{scopeView.name}
	formData[scopeUpload.name] = []string{scopeUpload.name}

	scope := selectedScopes(formData)

	expectedScope := scopeView.name + "," + scopeUpload.name

	if scope != expectedScope {
		t.Fatalf("got %s expected %s", scope, expectedScope)
	}
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

func Test_makeScopeOption(t *testing.T) {

	option := makeScopeOption(scopeUpload)

	if option == "" {
		t.Fatal("makeScopeOption returned something")
	}

	if strings.Contains(option, "type=\"checkbox\"") == false {
		t.Fatal("makeScopeOption should be a checkbox")
	}

	if strings.Contains(option, scopeUpload.name) == false {
		t.Fatal("makeScopeOption should include the scope name")
	}

	if strings.Contains(option, scopeUpload.requestMsg) == false {
		t.Fatal("makeScopeOption should include the scope detail")
	}

}
