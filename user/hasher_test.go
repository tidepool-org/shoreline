package user

import "testing"

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
			t.Fatalf("the hash should be 20 characters in length, but has %v", len(theHash))
		}
	} else {
		t.Fatalf("there should be no error given")
	}

}

func TestGeneratePasswordHash_NoId(t *testing.T) {

	if _, err := GeneratePasswordHash("", "th3P0rd", "some salt"); err == nil {
		t.Fatal("there should be an error when no id is given")
	}

}

func TestGeneratePasswordHash_NoPw(t *testing.T) {

	if _, err := GeneratePasswordHash("1234", "", "some salt"); err != nil {
		t.Fatal("there should NOT be an error when no pw is given")
	}

}

func TestGeneratePasswordHash_NoSalt(t *testing.T) {

	if _, err := GeneratePasswordHash("1234", "th3P0rd", ""); err == nil {
		t.Fatal("there should be an error when no pw is given")
	}

}

func TestGeneratePasswordHash(t *testing.T) {

	if pwHashed, err := GeneratePasswordHash("1234", "th3P0rd", "some salt"); err != nil {
		t.Fatal("there should be an error when no pw is given")
	} else {
		reHashed, _ := GeneratePasswordHash("1234", "th3P0rd", "some salt")

		if pwHashed != reHashed {
			t.Fatal("the two hash's should match")
		}

		badHashed, _ := GeneratePasswordHash("1235", "th3P0rd", "some salt")

		if pwHashed == badHashed {
			t.Fatal("the two hash's should NOT match as they have different userid's")
		}
	}

}
