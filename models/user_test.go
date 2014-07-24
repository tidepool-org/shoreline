package models

import (
	"testing"
)

func TestHasIdentifierForName(t *testing.T) {
	user := User{Name: "a name"}
	if valid := user.HasIdentifier(); valid != true {
		t.Fatalf("session value should have been set for token")
	}
}

func TestHasIdentifierForId(t *testing.T) {
	user := User{Id: "123-your-id"}
	if valid := user.HasIdentifier(); valid != true {
		t.Fatalf("session value should have been set for token")
	}
}

func TestHasIdentifierForEmail(t *testing.T) {
	user := User{Emails: []string{"test@foo.bar"}}
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
	user := User{Id: "123-user-id-you-know-me"}

	if err := user.HashPassword("my pw", "the salt"); err == nil {
		if user.PwHash == "" {
			t.Fatalf("the password should have been hashed")
		}
	} else {
		t.Fatalf("there should not have been an error")
	}

}

func TestPwHashWithEmptyParams(t *testing.T) {
	user := User{Id: "123-user-id-you-know-me"}

	if err := user.HashPassword("", ""); err == nil {
		t.Fatalf("there should be an error when the parameters are not passed")

	}

	if user.PwHash != "" {
		t.Fatalf("there was no password to hash so it should fail")
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
		if user.Hash == "" {
			t.Fatalf("the user hash should have been set")
		}
		if len(user.Hash) != 24 {
			t.Fatalf("the user hash should be 24 characters in length")
		}
		if user.Id == "" {
			t.Fatalf("the user id should have been set")
		}
		if len(user.Id) != 10 {
			t.Fatalf("the user id should be 10 characters in length")
		}
		if user.Name == "" {
			t.Fatalf("the user name should have been set")
		}
		if len(user.Emails) != 1 {
			t.Fatalf("the emails should have been set")
		}
	}

}
