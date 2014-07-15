package api

import (
	"testing"
)

func TestHasIdentifierForName(t *testing.T) {
	user := User{name: "a name"}
	if valid := user.HasIdentifier(); valid != true {
		t.Fatalf("session value should have been set for token")
	}
}

func TestHasIdentifierForId(t *testing.T) {
	user := User{id: "123-your-id"}
	if valid := user.HasIdentifier(); valid != true {
		t.Fatalf("session value should have been set for token")
	}
}

func TestHasIdentifierForEmail(t *testing.T) {
	user := User{emails: []string{"test@foo.bar"}}
	if valid := user.HasIdentifier(); valid != true {
		t.Fatalf("session value should have been set for token")
	}
}

func TestHasIdentifierWhenNonSet(t *testing.T) {
	user := User{}
	if valid := user.HasIdentifier(); valid != false {
		t.Fatalf("session value should have been set for token")
	}
}

func TestPwHash(t *testing.T) {
	user := User{id: "123-user-id-you-know-me"}

	if err := user.HashPassword("my pw", "the salt"); err == nil {
		if user.pwhash == "" {
			t.Fatalf("the password should have been hashed")
		}
	} else {
		t.Fatalf("there should not have been an error")
	}

}

func TestPwHashWithEmptyParams(t *testing.T) {
	user := User{id: "123-user-id-you-know-me"}

	if err := user.HashPassword("", ""); err == nil {
		t.Fatalf("there should be an error when the parameters are not passed")

	}

	if user.pwhash != "" {
		t.Fatalf("there was no password to hash so it should fail")
	}

}

func TestGenerateUniqueHashWithNoStringsParam(t *testing.T) {

	if _, err := generateUniqueHash([]string{}, 5); err == nil {
		t.Fatalf("this should have thrown an error as no strings were given")
	}

}

func TestGenerateUniqueHashWithNoLengthParam(t *testing.T) {

	if _, err := generateUniqueHash([]string{"one", "two", "miss a few", "99", "100"}, 0); err == nil {
		t.Fatalf("this should have thrown an error as lenth is 0")
	}

}

func TestGenerateUniqueHashLength(t *testing.T) {

	if theHash, err := generateUniqueHash([]string{"one", "two", "miss a few", "99", "100"}, 20); err == nil {
		if len(theHash) != 20 {
			t.Fatalf("the has should be 20 characters in length ", len(theHash))
		}
	} else {
		t.Fatalf("there should be no error given")
	}

}

func TestNewUserNoPw(t *testing.T) {

	if _, err := NewUser("jamie", "", []string{}); err == nil {
		t.Fatalf("should have given error as the password is not given")
	}

}

func TestNewUserNoName(t *testing.T) {

	if _, err := NewUser("", "3th3Hardw0y", []string{}); err == nil {
		t.Fatalf("should have given error as the name is not given")
	}

}

func TestNewUser(t *testing.T) {

	if user, err := NewUser("", "3th3Hardw0y", []string{"test@foo.bar"}); err == nil {
		if user.hash == "" {
			t.Fatalf("the user hash should have been set")
		}
		if len(user.hash) != 24 {
			t.Fatalf("the user hash should be 24 characters in length")
		}
		if user.id == "" {
			t.Fatalf("the user id should have been set")
		}
		if len(user.id) != 10 {
			t.Fatalf("the user id should be 10 characters in length")
		}
		if user.name == "" {
			t.Fatalf("the user name should have been set")
		}
		if len(user.emails) != 1 {
			t.Fatalf("the emails should have been set")
		}
	}

}
