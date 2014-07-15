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
