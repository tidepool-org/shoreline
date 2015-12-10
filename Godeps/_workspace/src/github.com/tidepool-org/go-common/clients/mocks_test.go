package clients

import (
	"testing"
)

//The purpose of this test is to ensure you canreply on the mocks

const USERID, GROUPID, TOKEN_MOCK = "123user", "456group", "this is a token"

func makeExpectedPermissons() map[string]Permissions {
	expected := make(map[string]Permissions)
	p := make(Permissions)
	p["userid"] = USERID
	expected["root"] = p
	return expected
}

func TestGatekeeperMock_UserInGroup(t *testing.T) {

	expected := makeExpectedPermissons()

	gkc := NewGatekeeperMock()

	if perms, err := gkc.UserInGroup(USERID, GROUPID); err != nil {
		t.Fatal("No error should be returned")
	} else if perms == nil || perms["root"]["userid"] != expected["root"]["userid"] {
		t.Fatalf("Perms where [%v] but expected [%v]", perms, expected)
	}
}
func TestGatekeeperMock_SetPermissions(t *testing.T) {

	gkc := NewGatekeeperMock()

	expected := makeExpectedPermissons()

	if perms, err := gkc.SetPermissions(USERID, GROUPID, expected["root"]); err != nil {
		t.Fatal("No error should be returned")
	} else if perms == nil || perms["root"]["userid"] != expected["root"]["userid"] {
		t.Fatalf("Perms where [%v] but expected [%v]", perms, expected)

	}
}

func TestSeagullMock_GetCollection(t *testing.T) {

	sc := NewSeagullMock()
	var col struct{ Something string }

	sc.GetCollection("123.456", "stuff", TOKEN_MOCK, &col)

	if col.Something != "anit no thing" {
		t.Error("Should have given mocked collection")
	}
}

func TestSeagullMock_GetPrivatePair(t *testing.T) {
	sc := NewSeagullMock()

	if pp := sc.GetPrivatePair("123.456", "Stuff", TOKEN_MOCK); pp == nil {
		t.Error("Should give us mocked private pair")
	}

}
