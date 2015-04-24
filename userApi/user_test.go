package userapi

import (
	"strings"
	"testing"
)

func Test_Name(t *testing.T) {

	casedName := "A Name"

	user := UserFromDetails(&UserDetail{Name: casedName})

	if user.Name == "" {
		t.Fatalf("the name should have been set")
	}

	if user.Name != strings.ToLower(casedName) {
		t.Fatalf("the name should be lowercase")
	}

}
func Test_Id(t *testing.T) {

	id := "123-your-id"
	user := UserFromDetails(&UserDetail{Id: id})

	if user.Id != id {
		t.Fatalf("the id should have been set")
	}
}
func Test_Emails(t *testing.T) {

	e1 := "test@foo.bar"
	e2 := "TEST@two.bar"

	emails := []string{e1, e2}
	user := UserFromDetails(&UserDetail{Emails: emails})

	if len(user.Emails) != 2 {
		t.Fatalf("there should be two emails")
	}

	if user.Emails[0] != emails[0] || user.Emails[1] != emails[1] {
		t.Fatalf("the emails should have been set")
	}

	if user.Emails[1] != e2 {
		t.Fatalf("the emails should keep the case as they were added")
	}
}
func Test_HashPassword(t *testing.T) {
	user := User{Id: "123-user-id-you-know-me"}

	if err := user.HashPassword("my pw", "the salt"); err == nil {
		if user.PwHash == "" {
			t.Fatalf("the password should have been hashed")
		}
	} else {
		t.Fatalf("there should not have been an error")
	}

}
func Test_HashPassword_WithEmptyParams(t *testing.T) {
	user := User{Id: "123-user-id-you-know-me"}

	if err := user.HashPassword("", ""); err == nil {
		t.Fatalf("there should be an error when the parameters are not passed")

	}

	if user.PwHash != "" {
		t.Fatalf("there was no password to hash so it should fail")
	}

}
func Test_NewUser_AsChild(t *testing.T) {

	theName := "The Kid"

	if childAcct, err := NewChildUser(&UserDetail{Name: theName}, "some salt"); err != nil {
		t.Fatalf("it is legit to create a user withuot a pw - this is known as a Child Account")
	} else {
		if childAcct.Name == theName {
			t.Fatalf("the user name should have been hashed")
		}
		if len(childAcct.Name) != 10 {
			t.Fatalf("the user name should be 10 characters in length")
		}
		if childAcct.Hash == "" {
			t.Fatalf("the user hash should have been set")
		}
		if len(childAcct.Hash) != 24 {
			t.Fatalf("the user hash should be 24 characters in length")
		}
		if childAcct.Id == "" {
			t.Fatalf("the user id should have been set")
		}
		if len(childAcct.Id) != 10 {
			t.Fatalf("the user id should be 10 characters in length")
		}
		if len(childAcct.Emails) != 0 {
			t.Fatalf("there should be no emails")
		}

		if childAcct.Verified == false {
			t.Fatalf("the child account should be verified by default")
		}

		//make another child account with the same name
		otherChildAcct, _ := NewChildUser(&UserDetail{Name: theName}, "some salt")

		if otherChildAcct.Name == childAcct.Name {
			t.Fatalf("the hashed names should be different")
		}
	}
}
func Test_NewUser_NoPw(t *testing.T) {

	if _, err := NewUser(&UserDetail{Name: "I have a name", Emails: []string{}}, "some salt"); err == nil {
		t.Fatalf("should have given error as the pw is not given")
	}

}
func Test_NewUser_NoName(t *testing.T) {

	if _, err := NewUser(&UserDetail{Name: "", Pw: "3th3Hardw0y", Emails: []string{}}, "some salt"); err == nil {
		t.Fatalf("should have given error as the name is not given")
	}

}
func Test_NewUser(t *testing.T) {

	name := "MixeD caSe"

	if user, err := NewUser(&UserDetail{Name: name, Pw: "3th3Hardw0y", Emails: []string{"test@foo.bar"}}, "some salt"); err == nil {
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
		//Name should be lowercase
		if user.Name == "" {
			t.Fatalf("the user name should have been set")
		}
		if user.Name == name {
			t.Fatalf("the user name should be lower case")
		}
		if user.Name != strings.ToLower(name) {
			t.Fatalf("the user name should match the lowercase version of the given name")
		}

		if len(user.Emails) != 1 {
			t.Fatalf("the emails should have been set")
		}

		if user.Verified {
			t.Fatalf("the user account should not be verified by default")
		}
	}

}
func Test_IsVerified(t *testing.T) {

	userWithSecret, _ := NewUser(&UserDetail{Name: "one", Pw: "3th3Hardw0y", Emails: []string{"test+secret@foo.bar"}}, "some salt")
	user, _ := NewUser(&UserDetail{Name: "two", Pw: "3th3Hardw0y", Emails: []string{"test@foo.bar"}}, "some salt")

	//no secret
	if userWithSecret.IsVerified("") == true {
		t.Fatalf("the user should not have been verified")
	}

	if user.IsVerified("") == true {
		t.Fatalf("the user should not have been verified")
	}

	//with secret
	if userWithSecret.IsVerified("+secret") == false {
		t.Fatalf("the user should say they are verified as we both have the secret")
	}

	if user.IsVerified("+secret") == true {
		t.Fatalf("the user should say they are verified as they don't have the secret")
	}

}
