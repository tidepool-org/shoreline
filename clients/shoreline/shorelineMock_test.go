package shoreline

import (
	"testing"

	"github.com/mdblp/shoreline/schema"
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
func TestMock(t *testing.T) {

	const tokenMock = "this is a token"

	client := NewMock(tokenMock)

	if err := client.Start(); err != nil {
		t.Errorf("Failed start with error[%v]", err)
	}

	if tok := client.TokenProvide(); tok != tokenMock {
		t.Errorf("Unexpected token[%s]", tok)
	}

	if usr, token, err := client.Login("billy", "howdy"); err != nil {
		t.Errorf("Failed start with error[%v]", err)
	} else {
		if usr == nil {
			t.Error("Should give us a fake usr details")
		}
		if token == "" {
			t.Error("Should give us a fake token")
		}
	}

	if checkedTd := client.CheckToken(tokenMock); checkedTd == nil {
		t.Error("Should give us token data")
	}

	if usr, _ := client.GetUser("billy@howdy.org", tokenMock); usr == nil {
		t.Error("Should give us a mock user")
	}

	if usr, _ := client.GetUser("a.Clinic@howdy.org", tokenMock); usr != nil {
		if !contains(usr.Roles, "hcp") {
			t.Error("Should give us an hcp account")
		}
	}

	username := "name"
	password := "myN3wPw"
	user := schema.UserUpdate{Username: &username, Emails: &[]string{"an@email.org"}, Password: &password}

	if err := client.UpdateUser("123", user, tokenMock); err != nil {
		t.Error("Should return no error on success")
	}

	if sd, se := client.Signup("username", "password", "email@place.org"); sd == nil || se != nil {
		t.Errorf("Signup not return err[%s]", se.Error())
	}

}
