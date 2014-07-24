package models

import (
	"testing"
)

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
