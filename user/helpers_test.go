package user

import (
	"reflect"
	"testing"
)

func Test_FirstStringNotEmpty_None(t *testing.T) {
	result := firstStringNotEmpty()
	if result != "" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_FirstStringNotEmpty_One(t *testing.T) {
	result := firstStringNotEmpty("one")
	if result != "one" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_FirstStringNotEmpty_Two(t *testing.T) {
	result := firstStringNotEmpty("", "two")
	if result != "two" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_FirstStringNotEmpty_Blank(t *testing.T) {
	result := firstStringNotEmpty("", "", "")
	if result != "" {
		t.Fatalf("Unexpected result: %#v", result)
	}
}

func Test_AsSerializableUser_Interface(t *testing.T) {
	serializableUser := shoreline.asSerializableUser(&User{}, false)
	if serializableUser == nil {
		t.Fatalf("Serializable user is nil")
	}
	if _, ok := serializableUser.(map[string]interface{}); !ok {
		t.Fatalf("Serializable user [%#v] does not match expected interface", serializableUser)
	}
}

func Test_AsSerializableUser_UserId(t *testing.T) {
	user := &User{Id: "1234567890"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 1 || serializableUser["userid"] != user.Id {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for userid", serializableUser, user)
	}
}

func Test_AsSerializableUser_Username(t *testing.T) {
	user := &User{Username: "tester@test.com"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || serializableUser["username"] != user.Username || serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for username", serializableUser, user)
	}
}

func Test_AsSerializableUser_TemporaryCustodialUsername(t *testing.T) {
	user := &User{Username: "unclaimed-custodial-automation+123456789@tidepool.org"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if serializableUser["username"] != nil {
		t.Fatalf("Custodial username '%v' was serialized when it shouldn't have been", serializableUser["username"])
	}
}

func Test_AsSerializableUser_TemporaryCustodialEmails(t *testing.T) {
	user := &User{Emails: []string{"unclaimed-custodial-automation+123456789@tidepool.org"}}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if serializableUser["emails"] != nil {
		t.Fatalf("Custodial emails '%v' were serialized when they shouldn't have been", serializableUser["emails"])
	}
}

func Test_AsSerializableUser_Emails(t *testing.T) {
	user := &User{Emails: []string{"tester@test.com"}}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || !reflect.DeepEqual(serializableUser["emails"], user.Emails) || serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for emails", serializableUser, user)
	}
}

func Test_AsSerializableUser_Roles(t *testing.T) {
	user := &User{Roles: []string{"clinic"}}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 1 || !reflect.DeepEqual(serializableUser["roles"], user.Roles) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for roles", serializableUser, user)
	}
}

func Test_AsSerializableUser_TermsAccepted(t *testing.T) {
	user := &User{TermsAccepted: "2016-01-01T00:00:00-08:00"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 1 || serializableUser["termsAccepted"] != user.TermsAccepted {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for termsAccepted", serializableUser, user)
	}
}

func Test_AsSerializableUser_EmailVerified_True(t *testing.T) {
	user := &User{Username: "tester@test.com", EmailVerified: true}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || serializableUser["username"] != user.Username || !serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for emailVerified as true", serializableUser, user)
	}
}

func Test_AsSerializableUser_EmailVerified_False(t *testing.T) {
	user := &User{Username: "tester@test.com", EmailVerified: false}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 2 || serializableUser["username"] != user.Username || serializableUser["emailVerified"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for emailVerified as false", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_True_Server(t *testing.T) {
	user := &User{PwHash: "abcdefghijkl"}
	serializableUser := shoreline.asSerializableUser(user, true).(map[string]interface{})
	if len(serializableUser) != 1 || !serializableUser["passwordExists"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_True_NotServer(t *testing.T) {
	user := &User{PwHash: "abcdefghijkl"}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 0 {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_False_Server(t *testing.T) {
	user := &User{}
	serializableUser := shoreline.asSerializableUser(user, true).(map[string]interface{})
	if len(serializableUser) != 1 || serializableUser["passwordExists"].(bool) {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}

func Test_AsSerializableUser_PasswordExists_False_NotServer(t *testing.T) {
	user := &User{}
	serializableUser := shoreline.asSerializableUser(user, false).(map[string]interface{})
	if len(serializableUser) != 0 {
		t.Fatalf("Serializable user [%#v] does not match User [%#v] for passwordExists as not server", serializableUser, user)
	}
}
