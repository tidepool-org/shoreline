package shoreline

import (
	"testing"
)

func TestMock(t *testing.T) {

	const TOKEN_MOCK = "this is a token"

	client := NewMock(TOKEN_MOCK)

	if err := client.Start(); err != nil {
		t.Errorf("Failed start with error[%v]", err)
	}

	if tok := client.TokenProvide(); tok != TOKEN_MOCK {
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

	if checkedTd := client.CheckToken(TOKEN_MOCK); checkedTd == nil {
		t.Error("Should give us token data")
	}

	if sd, se := client.Signup("username", "password", "email@place.org"); sd == nil || se != nil {
		t.Errorf("Signup not return err[%s]", se.Error())
	}

}
