package models

import (
	"testing"
)

func TestGenerateHash_NotEnoughArgs(t *testing.T) {

	if _, err := GenerateHash("stuff", "th3P0rd"); err == nil {
		t.Fatal("there should be an error not enough data is given")
	}

}

func TestGenerateHash(t *testing.T) {

	if pwHashed, err := GenerateHash("1234", "th3P0rd", "some salt", "6789"); err != nil {
		t.Fatal("there should be an error when no pw is given")
	} else {
		reHashed, _ := GenerateHash("1234", "th3P0rd", "some salt", "6789")

		if pwHashed != reHashed {
			t.Fatal("the two hash's should match")
		}

		otherHash, _ := GenerateHash("1235", "th3P0rd", "some salt", "6789")

		if pwHashed == otherHash {
			t.Fatal("the two hash's should NOT match as they have different userid's")
		}
	}

}
