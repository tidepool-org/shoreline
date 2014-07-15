package api

import (
	"log"
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

	user.HashPassword("my pw", "the salt")

	if user.pwhash == "" {
		t.Fatalf("the password should have been hashed")
	}
	log.Println("pw hash: ", user.pwhash)

}

func TestPwHashWithEmptyParams(t *testing.T) {
	user := User{id: "123-user-id-you-know-me"}

	user.HashPassword("", "")

	if user.pwhash != "" {
		t.Fatalf("there was no password to hash so it should fail")
	}
	log.Println("pw hash: ", user.pwhash)

}
