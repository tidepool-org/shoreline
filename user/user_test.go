package user

import (
	"reflect"
	"strings"
	"testing"
)

func Test_ExtractBool_Missing(t *testing.T) {
	source := map[string]interface{}{"additional": "unexpected"}
	result, ok := ExtractBool(source, "target")
	if result != nil || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractBool_Present(t *testing.T) {
	source := map[string]interface{}{"target": true, "additional": "unexpected"}
	result, ok := ExtractBool(source, "target")
	if !*result || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractBool_Present_NotBool(t *testing.T) {
	source := map[string]interface{}{"target": "unexpected", "additional": "unexpected"}
	result, ok := ExtractBool(source, "target")
	if result != nil || ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractString_Missing(t *testing.T) {
	source := map[string]interface{}{"additional": "unexpected"}
	result, ok := ExtractString(source, "target")
	if result != nil || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractString_Present(t *testing.T) {
	source := map[string]interface{}{"target": "expected", "additional": "unexpected"}
	result, ok := ExtractString(source, "target")
	if *result != "expected" || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractString_Present_NotString(t *testing.T) {
	source := map[string]interface{}{"target": true, "additional": "unexpected"}
	result, ok := ExtractString(source, "target")
	if result != nil || ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractArray_Missing(t *testing.T) {
	source := map[string]interface{}{"additional": "unexpected"}
	result, ok := ExtractArray(source, "target")
	if result != nil || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractArray_Present(t *testing.T) {
	source := map[string]interface{}{"target": []interface{}{"expected", "expected-2", "expected-3"}, "additional": "unexpected"}
	result, ok := ExtractArray(source, "target")
	if !reflect.DeepEqual(result, []interface{}{"expected", "expected-2", "expected-3"}) || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractArray_Present_NotArray(t *testing.T) {
	source := map[string]interface{}{"target": true, "additional": "unexpected"}
	result, ok := ExtractArray(source, "target")
	if result != nil || ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractStringArray_Missing(t *testing.T) {
	source := map[string]interface{}{"additional": "unexpected"}
	result, ok := ExtractStringArray(source, "target")
	if result != nil || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractStringArray_Present(t *testing.T) {
	source := map[string]interface{}{"target": []interface{}{"expected", "expected-2", "expected-3"}, "additional": "unexpected"}
	result, ok := ExtractStringArray(source, "target")
	if !reflect.DeepEqual(result, []string{"expected", "expected-2", "expected-3"}) || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractStringArray_Present_NotStringArray(t *testing.T) {
	source := map[string]interface{}{"target": true, "additional": "unexpected"}
	result, ok := ExtractStringArray(source, "target")
	if result != nil || ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractStringMap_Missing(t *testing.T) {
	source := map[string]interface{}{"additional": "unexpected"}
	result, ok := ExtractStringMap(source, "target")
	if result != nil || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractStringMap_Present(t *testing.T) {
	source := map[string]interface{}{"target": map[string]interface{}{"expected": "expected-2"}, "additional": "unexpected"}
	result, ok := ExtractStringMap(source, "target")
	if !reflect.DeepEqual(result, map[string]interface{}{"expected": "expected-2"}) || !ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_ExtractStringMap_Present_NotStringMap(t *testing.T) {
	source := map[string]interface{}{"target": true, "additional": "unexpected"}
	result, ok := ExtractStringMap(source, "target")
	if result != nil || ok {
		t.Fatalf("Unexpected result [%#v, %t]", result, ok)
	}
}

func Test_IsValidEmail_Invalid(t *testing.T) {
	invalidEmails := []string{"", "a", "a@", "a@z", "a@z.", "a@z.c", ".co", "z.co", "@z.co", "a@b@z.co", "a b@z.co", "a@z$z.co", "a@x#z.co"}
	for _, invalidEmail := range invalidEmails {
		if IsValidEmail(invalidEmail) {
			t.Fatalf("Invalid email %s is unexpectedly valid", invalidEmail)
		}
	}
}

func Test_IsValidEmail_Valid(t *testing.T) {
	validEmails := []string{"a@z.com", "a-b@z.com", "a$b@z.com", "a#b@z.com", "a@stuvwxyz.co", "a@z.company"}
	for _, validEmail := range validEmails {
		if !IsValidEmail(validEmail) {
			t.Fatalf("Valid email %s is unexpectedly invalid", validEmail)
		}
	}
}

func Test_IsValidRole_Invalid(t *testing.T) {
	invalidRoles := []string{"", "abcdefg"}
	for _, invalidRole := range invalidRoles {
		if IsValidRole(invalidRole) {
			t.Fatalf("Invalid role %s is unexpectedly valid", invalidRole)
		}
	}
}

func Test_IsValidRole_Valid(t *testing.T) {
	validRoles := []string{"hcp", "caregiver"}
	for _, validRole := range validRoles {
		if !IsValidRole(validRole) {
			t.Fatalf("Valid role %s is unexpectedly invalid", validRole)
		}
	}
}

func Test_IsValidPassword_Invalid(t *testing.T) {
	invalidPasswords := []string{"", "1", "1234567", "123  678", "1234567890123456789012345678901234  789012345678901234567890123456789012", "1234567890123456789012345678901234567890123456789012345678901234567890123"}
	for _, invalidPassword := range invalidPasswords {
		if IsValidPassword(invalidPassword) {
			t.Fatalf("Invalid password %s is unexpectedly valid", invalidPassword)
		}
	}
}

func Test_IsValidPassword_Valid(t *testing.T) {
	validPasswords := []string{"12345678", "123456789012345678901234567890123456789012345678901234567890123456789012"}
	for _, validPassword := range validPasswords {
		if !IsValidPassword(validPassword) {
			t.Fatalf("Valid password %s is unexpectedly invalid", validPassword)
		}
	}
}

func Test_IsValidDate_Invalid(t *testing.T) {
	invalidDates := []string{"", "a", "aaaa-aa-aa", "2016-01-01T00:00:00-08:00", "2016-13-32"}
	for _, invalidDate := range invalidDates {
		if IsValidDate(invalidDate) {
			t.Fatalf("Invalid date %s is unexpectedly valid", invalidDate)
		}
	}
}

func Test_IsValidDate_Valid(t *testing.T) {
	validDates := []string{"2016-01-01", "2015-12-31"}
	for _, validDate := range validDates {
		if !IsValidDate(validDate) {
			t.Fatalf("Valid date %s is unexpectedly invalid", validDate)
		}
	}
}

func Test_IsValidTimestamp_Invalid(t *testing.T) {
	invalidTimestamps := []string{"", "a", "aaaa-aa-aaTaa:aa:aa-aa:aa", "2016-01-01T00:00:00Z", "2016-13-32T24:60:62-24:30"}
	for _, invalidTimestamp := range invalidTimestamps {
		if IsValidTimestamp(invalidTimestamp) {
			t.Fatalf("Invalid timestamp %s is unexpectedly valid", invalidTimestamp)
		}
	}
}

func Test_IsValidTimestamp_Valid(t *testing.T) {
	validTimestamps := []string{"2016-01-01T00:00:00-00:00", "2015-12-31T23:59:59-23:30"}
	for _, validTimestamp := range validTimestamps {
		if !IsValidTimestamp(validTimestamp) {
			t.Fatalf("Valid timestamp %s is unexpectedly invalid", validTimestamp)
		}
	}
}

func Test_NewUserDetails_ExtractFromJSON_InvalidJSON(t *testing.T) {
	source := ""
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err == nil {
		t.Fatalf("Unexpected success for invalid JSON")
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil {
		t.Fatalf("Unexpected fields present on error for invalid JSON")
	}
}

func Test_NewUserDetails_ExtractFromJSON_InvalidUsername(t *testing.T) {
	source := "{\"username\": true, \"emails\": [\"b@y.com\"], \"password\": \"12345678\", \"roles\": [\"hcp\"]}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_username_invalid {
		t.Fatalf("Unexpected error for invalid username: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil {
		t.Fatalf("Unexpected fields present on error for invalid username")
	}
}

func Test_NewUserDetails_ExtractFromJSON_InvalidEmails(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": true, \"password\": \"12345678\", \"roles\": [\"hcp\"]}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_emails_invalid {
		t.Fatalf("Unexpected error for invalid emails: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil {
		t.Fatalf("Unexpected fields present on error for invalid emails")
	}
}

func Test_NewUserDetails_ExtractFromJSON_InvalidPassword(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": true, \"roles\": [\"hcp\"]}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_password_invalid {
		t.Fatalf("Unexpected error for invalid password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil {
		t.Fatalf("Unexpected fields present on error for invalid password")
	}
}

func Test_NewUserDetails_ExtractFromJSON_InvalidRoles(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": true}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_roles_invalid {
		t.Fatalf("Unexpected error for invalid roles: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil {
		t.Fatalf("Unexpected fields present on error for invalid roles")
	}
}

func Test_NewUserDetails_ExtractFromJSON_ValidAll(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": [\"hcp\"], \"ignored\": true}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with all: %#v", err)
	}
	if *details.Username != "a@z.co" || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) || *details.Password != "12345678" || !reflect.DeepEqual(details.Roles, []string{"hcp"}) {
		t.Fatalf("Missing fields that should be present on success with all")
	}
}

func Test_NewUserDetails_ExtractFromJSON_ValidUsername(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"ignored\": true}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with username: %#v", err)
	}
	if *details.Username != "a@z.co" || details.Emails != nil || details.Password != nil || details.Roles != nil {
		t.Fatalf("Missing fields that should be present on success with username")
	}
}

func Test_NewUserDetails_ExtractFromJSON_ValidEmails(t *testing.T) {
	source := "{\"emails\": [\"b@y.co\"], \"ignored\": true}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with emails: %#v", err)
	}
	if details.Username != nil || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) || details.Password != nil || details.Roles != nil {
		t.Fatalf("Missing fields that should be present on success with emails")
	}
}

func Test_NewUserDetails_ExtractFromJSON_ValidPassword(t *testing.T) {
	source := "{\"password\": \"12345678\", \"ignored\": true}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || *details.Password != "12345678" || details.Roles != nil {
		t.Fatalf("Missing fields that should be present on success with password")
	}
}

func Test_NewUserDetails_ExtractFromJSON_ValidRoles(t *testing.T) {
	source := "{\"roles\": [\"hcp\"], \"ignored\": true}"
	details := &NewUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with roles: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || !reflect.DeepEqual(details.Roles, []string{"hcp"}) {
		t.Fatalf("Missing fields that should be present on success with roles")
	}
}

func Test_NewUserDetails_Validate_Username_Missing(t *testing.T) {
	password := "12345678"
	details := &NewUserDetails{Emails: []string{"b@y.co", "c@x.co"}, Password: &password}
	err := details.Validate()
	if err != User_error_username_missing {
		t.Fatalf("Unexpected error for username missing: %#v", err)
	}
}

func Test_NewUserDetails_Validate_Username_Invalid(t *testing.T) {
	username := "a"
	password := "12345678"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}, Password: &password}
	err := details.Validate()
	if err != User_error_username_invalid {
		t.Fatalf("Unexpected error for username invalid: %#v", err)
	}
}

func Test_NewUserDetails_Validate_Emails_Missing(t *testing.T) {
	username := "a@z.co"
	password := "12345678"
	details := &NewUserDetails{Username: &username, Password: &password}
	err := details.Validate()
	if err != User_error_emails_missing {
		t.Fatalf("Unexpected error for emails missing: %#v", err)
	}
}

func Test_NewUserDetails_Validate_Emails_Invalid(t *testing.T) {
	username := "a@z.co"
	password := "12345678"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c"}, Password: &password}
	err := details.Validate()
	if err != User_error_emails_invalid {
		t.Fatalf("Unexpected error for emails invalid: %#v", err)
	}
}

func Test_NewUserDetails_Validate_Password_Missing(t *testing.T) {
	username := "a@z.co"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}}
	err := details.Validate()
	if err != User_error_password_missing {
		t.Fatalf("Unexpected error for password missing: %#v", err)
	}
}

func Test_NewUserDetails_Validate_Password_Invalid(t *testing.T) {
	username := "a@z.co"
	password := "1234567"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}, Password: &password}
	err := details.Validate()
	if err != User_error_password_invalid {
		t.Fatalf("Unexpected error for password invalid: %#v", err)
	}
}

func Test_NewUserDetails_Validate_Roles_Invalid(t *testing.T) {
	username := "a@z.co"
	password := "12345678"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}, Password: &password, Roles: []string{"invalid"}}
	err := details.Validate()
	if err != User_error_roles_invalid {
		t.Fatalf("Unexpected error for roles invalid: %#v", err)
	}
}

func Test_NewUserDetails_Validate_Valid(t *testing.T) {
	username := "a@z.co"
	password := "12345678"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}, Password: &password, Roles: []string{"hcp"}}
	err := details.Validate()
	if err != nil {
		t.Fatalf("Unexpected error for valid: %#v", err)
	}
}

func Test_ParseNewUserDetails_InvalidJSON(t *testing.T) {
	source := ""
	details, err := ParseNewUserDetails(strings.NewReader(source))
	if err == nil {
		t.Fatalf("Unexpected success for invalid JSON")
	}
	if details != nil {
		t.Fatalf("Unexpected details for invalid JSON")
	}
}

func Test_ParseNewUserDetails_ValidAll(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": [\"hcp\"]}"
	details, err := ParseNewUserDetails(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with all: %#v", err)
	}
	if details == nil {
		t.Fatalf("Missing details on success with all")
	}
	if *details.Username != "a@z.co" || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) || *details.Password != "12345678" || !reflect.DeepEqual(details.Roles, []string{"hcp"}) {
		t.Fatalf("Missing fields that should be present on success with all")
	}
}

func Test_NewUser_MissingDetails(t *testing.T) {
	salt := "abc"
	user, err := NewUser(nil, salt)
	if err == nil {
		t.Fatalf("Unexpected success for missing details")
	}
	if user != nil {
		t.Fatalf("User is not nil for missing details")
	}
}

func Test_NewUser_InvalidDetails(t *testing.T) {
	username := "a"
	details := &NewUserDetails{Username: &username}
	salt := "abc"
	user, err := NewUser(details, salt)
	if err == nil {
		t.Fatalf("Unexpected success for invalid details")
	}
	if user != nil {
		t.Fatalf("User is not nil for invalid details")
	}
}

func Test_NewUser_MissingSalt(t *testing.T) {
	username := "a@z.co"
	password := "12345678"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}, Password: &password}
	user, err := NewUser(details, "")
	if err == nil {
		t.Fatalf("Unexpected success for missing salt")
	}
	if user != nil {
		t.Fatalf("User is not nil for missing salt")
	}
}

func Test_NewUser_Valid(t *testing.T) {
	username := "a@z.co"
	password := "12345678"
	details := &NewUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}, Password: &password, Roles: []string{"hcp"}}
	salt := "abc"
	user, err := NewUser(details, salt)
	if err != nil {
		t.Fatalf("Unexpected error for valid: %#v", err)
	}
	if user == nil {
		t.Fatalf("User is nil for valid")
	}
	if user.Username != *details.Username || !reflect.DeepEqual(user.Emails, details.Emails) {
		t.Fatalf("Fields do not match on success")
	}
	if !user.PasswordsMatch(*details.Password, salt) {
		t.Fatalf("Password does not match on success")
	}
	if !reflect.DeepEqual(details.Roles, []string{"hcp"}) {
		t.Fatalf("Roles do not match on success")
	}
	if user.Id == "" || user.Hash == "" {
		t.Fatalf("Missing fields that should be present on success")
	}
	if user.TermsAccepted != "" || user.EmailVerified || len(user.Private) > 0 {
		t.Fatalf("Found fields that not should be present on success")
	}
}

func Test_NewCustodialUserDetails_ExtractFromJSON_InvalidJSON(t *testing.T) {
	source := ""
	details := &NewCustodialUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err == nil {
		t.Fatalf("Unexpected success for invalid JSON")
	}
	if details.Username != nil || details.Emails != nil {
		t.Fatalf("Unexpected fields present on error for invalid JSON")
	}
}

func Test_NewCustodialUserDetails_ExtractFromJSON_InvalidUsername(t *testing.T) {
	source := "{\"username\": true, \"emails\": [\"b@y.com\"]}"
	details := &NewCustodialUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_username_invalid {
		t.Fatalf("Unexpected error for invalid username: %#v", err)
	}
	if details.Username != nil || details.Emails != nil {
		t.Fatalf("Unexpected fields present on error for invalid username")
	}
}

func Test_NewCustodialUserDetails_ExtractFromJSON_InvalidEmails(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": true}"
	details := &NewCustodialUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_emails_invalid {
		t.Fatalf("Unexpected error for invalid emails: %#v", err)
	}
	if details.Username != nil || details.Emails != nil {
		t.Fatalf("Unexpected fields present on error for invalid emails")
	}
}

func Test_NewCustodialUserDetails_ExtractFromJSON_ValidAll(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"ignored\": true}"
	details := &NewCustodialUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with all: %#v", err)
	}
	if *details.Username != "a@z.co" || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) {
		t.Fatalf("Missing fields that should be present on success with all")
	}
}

func Test_NewCustodialUserDetails_ExtractFromJSON_ValidUsername(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"ignored\": true}"
	details := &NewCustodialUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with username: %#v", err)
	}
	if *details.Username != "a@z.co" || details.Emails != nil {
		t.Fatalf("Missing fields that should be present on success with username")
	}
}

func Test_NewCustodialUserDetails_ExtractFromJSON_ValidEmails(t *testing.T) {
	source := "{\"emails\": [\"b@y.co\"], \"ignored\": true}"
	details := &NewCustodialUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with emails: %#v", err)
	}
	if details.Username != nil || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) {
		t.Fatalf("Missing fields that should be present on success with emails")
	}
}

func Test_NewCustodialUserDetails_ExtractFromJSON_ValidNone(t *testing.T) {
	source := "{\"ignored\": true}"
	details := &NewCustodialUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with emails: %#v", err)
	}
	if details.Username != nil || details.Emails != nil {
		t.Fatalf("Missing fields that should be present on success with emails")
	}
}

func Test_NewCustodialUserDetails_Validate_Username_Missing(t *testing.T) {
	details := &NewCustodialUserDetails{Emails: []string{"b@y.co", "c@x.co"}}
	err := details.Validate()
	if err != nil {
		t.Fatalf("Unexpected error for username missing: %#v", err)
	}
}

func Test_NewCustodialUserDetails_Validate_Username_Invalid(t *testing.T) {
	username := "a"
	details := &NewCustodialUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}}
	err := details.Validate()
	if err != User_error_username_invalid {
		t.Fatalf("Unexpected error for username invalid: %#v", err)
	}
}

func Test_NewCustodialUserDetails_Validate_Emails_Missing(t *testing.T) {
	username := "a@z.co"
	details := &NewCustodialUserDetails{Username: &username}
	err := details.Validate()
	if err != nil {
		t.Fatalf("Unexpected error for emails missing: %#v", err)
	}
}

func Test_NewCustodialUserDetails_Validate_Emails_Invalid(t *testing.T) {
	username := "a@z.co"
	details := &NewCustodialUserDetails{Username: &username, Emails: []string{"b@y.co", "c"}}
	err := details.Validate()
	if err != User_error_emails_invalid {
		t.Fatalf("Unexpected error for emails invalid: %#v", err)
	}
}

func Test_NewCustodialUserDetails_Validate_Valid_All(t *testing.T) {
	username := "a@z.co"
	details := &NewCustodialUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}}
	err := details.Validate()
	if err != nil {
		t.Fatalf("Unexpected error for valid: %#v", err)
	}
}

func Test_NewCustodialUserDetails_Validate_Valid_None(t *testing.T) {
	details := &NewCustodialUserDetails{}
	err := details.Validate()
	if err != nil {
		t.Fatalf("Unexpected error for valid: %#v", err)
	}
}

func Test_ParseNewCustodialUserDetails_InvalidJSON(t *testing.T) {
	source := ""
	details, err := ParseNewCustodialUserDetails(strings.NewReader(source))
	if err == nil {
		t.Fatalf("Unexpected success for invalid JSON")
	}
	if details != nil {
		t.Fatalf("Unexpected details for invalid JSON")
	}
}

func Test_ParseNewCustodialUserDetails_ValidAll(t *testing.T) {
	source := "{\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"]}"
	details, err := ParseNewCustodialUserDetails(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with all: %#v", err)
	}
	if details == nil {
		t.Fatalf("Missing details on success with all")
	}
	if *details.Username != "a@z.co" || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) {
		t.Fatalf("Missing fields that should be present on success with all")
	}
}

func Test_ParseNewCustodialUserDetails_ValidNone(t *testing.T) {
	source := "{}"
	details, err := ParseNewCustodialUserDetails(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with all: %#v", err)
	}
	if details == nil {
		t.Fatalf("Missing details on success with all")
	}
	if details.Username != nil || details.Emails != nil {
		t.Fatalf("Missing fields that should be present on success with all")
	}
}

func Test_NewCustodialUser_MissingDetails(t *testing.T) {
	salt := "abc"
	user, err := NewCustodialUser(nil, salt)
	if err == nil {
		t.Fatalf("Unexpected success for missing details")
	}
	if user != nil {
		t.Fatalf("User is not nil for missing details")
	}
}

func Test_NewCustodialUser_InvalidDetails(t *testing.T) {
	username := "a"
	details := &NewCustodialUserDetails{Username: &username}
	salt := "abc"
	user, err := NewCustodialUser(details, salt)
	if err == nil {
		t.Fatalf("Unexpected success for invalid details")
	}
	if user != nil {
		t.Fatalf("User is not nil for invalid details")
	}
}

func Test_NewCustodialUser_ValidAll(t *testing.T) {
	username := "a@z.co"
	details := &NewCustodialUserDetails{Username: &username, Emails: []string{"b@y.co", "c@x.co"}}
	salt := "abc"
	user, err := NewCustodialUser(details, salt)
	if err != nil {
		t.Fatalf("Unexpected error for valid: %#v", err)
	}
	if user == nil {
		t.Fatalf("User is nil for valid")
	}
	if user.Username != *details.Username || !reflect.DeepEqual(user.Emails, details.Emails) {
		t.Fatalf("Fields do not match on success")
	}
	if user.Id == "" || user.Hash == "" {
		t.Fatalf("Missing fields that should be present on success")
	}
	if user.PwHash != "" || user.TermsAccepted != "" || user.EmailVerified || len(user.Private) > 0 {
		t.Fatalf("Found fields that not should be present on success")
	}
}

func Test_NewCustodialUser_ValidNone(t *testing.T) {
	details := &NewCustodialUserDetails{}
	salt := "abc"
	user, err := NewCustodialUser(details, salt)
	if err != nil {
		t.Fatalf("Unexpected error for valid: %#v", err)
	}
	if user == nil {
		t.Fatalf("User is nil for valid")
	}
	if user.Username != "" || len(user.Emails) != 0 {
		t.Fatalf("Fields do not match on success")
	}
	if user.Id == "" || user.Hash == "" {
		t.Fatalf("Missing fields that should be present on success")
	}
	if user.PwHash != "" || user.TermsAccepted != "" || user.EmailVerified || len(user.Private) > 0 {
		t.Fatalf("Found fields that not should be present on success")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_InvalidJSON(t *testing.T) {
	source := ""
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err == nil {
		t.Fatalf("Unexpected success for invalid JSON")
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid JSON")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_MissingUpdates(t *testing.T) {
	source := "{\"ignored\": {}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err == nil {
		t.Fatalf("Unexpected success for invalid JSON")
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid JSON")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_InvalidUsername(t *testing.T) {
	source := "{\"updates\": {\"username\": true, \"emails\": [\"b@y.com\"], \"password\": \"12345678\", \"roles\": [\"hcp\"], \"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"emailVerified\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_username_invalid {
		t.Fatalf("Unexpected error for invalid username: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid username")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_InvalidEmails(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": true, \"password\": \"12345678\", \"roles\": [\"hcp\"], \"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"emailVerified\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_emails_invalid {
		t.Fatalf("Unexpected error for invalid emails: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid emails")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_InvalidPassword(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": true, \"roles\": [\"hcp\"], \"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"emailVerified\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_new_password_invalid {
		t.Fatalf("Unexpected error for invalid password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid password")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_InvalidRoles(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": [true], \"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"emailVerified\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_roles_invalid {
		t.Fatalf("Unexpected error for invalid roles: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid roles")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_InvalidTermsAccepted(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": [\"hcp\"], \"termsAccepted\": true, \"emailVerified\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_terms_accepted_invalid {
		t.Fatalf("Unexpected error for invalid password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid password")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_InvalidEmailVerified(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": [\"hcp\"], \"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"emailVerified\": \"unexpected\"}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != User_error_email_verified_invalid {
		t.Fatalf("Unexpected error for invalid password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Unexpected fields present on error for invalid password")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_ValidAll(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": [\"hcp\"], \"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"emailVerified\": true, \"ignored\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with all: %#v", err)
	}
	if *details.Username != "a@z.co" || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) || *details.Password != "12345678" || !reflect.DeepEqual(details.Roles, []string{"hcp"}) || *details.TermsAccepted != "2016-01-01T12:00:00-08:00" || !*details.EmailVerified {
		t.Fatalf("Missing fields that should be present on success with all")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_ValidUsername(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"ignored\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with username: %#v", err)
	}
	if *details.Username != "a@z.co" || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Missing fields that should be present on success with username")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_ValidEmails(t *testing.T) {
	source := "{\"updates\": {\"emails\": [\"b@y.co\"], \"ignored\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with emails: %#v", err)
	}
	if details.Username != nil || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Missing fields that should be present on success with emails")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_ValidPassword(t *testing.T) {
	source := "{\"updates\": {\"password\": \"12345678\", \"ignored\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || *details.Password != "12345678" || details.Roles != nil || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Missing fields that should be present on success with password")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_ValidRoles(t *testing.T) {
	source := "{\"updates\": {\"roles\": [\"hcp\"], \"ignored\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with roles: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || !reflect.DeepEqual(details.Roles, []string{"hcp"}) || details.TermsAccepted != nil || details.EmailVerified != nil {
		t.Fatalf("Missing fields that should be present on success with roles")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_ValidTermsAccepted(t *testing.T) {
	source := "{\"updates\": {\"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"ignored\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || *details.TermsAccepted != "2016-01-01T12:00:00-08:00" || details.EmailVerified != nil {
		t.Fatalf("Missing fields that should be present on success with password")
	}
}

func Test_UpdateUserDetails_ExtractFromJSON_ValidEmailVerified(t *testing.T) {
	source := "{\"updates\": {\"emailVerified\": true, \"ignored\": true}}"
	details := &UpdateUserDetails{}
	err := details.ExtractFromJSON(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with password: %#v", err)
	}
	if details.Username != nil || details.Emails != nil || details.Password != nil || details.Roles != nil || details.TermsAccepted != nil || !*details.EmailVerified {
		t.Fatalf("Missing fields that should be present on success with password")
	}
}

func Test_UpdateUserDetails_Validate_No_Payload(t *testing.T) {
	details := &UpdateUserDetails{}
	err := details.Validate()
	if err != nil {
		t.Fatalf("Unexpected error for empty payload: %#v", err)
	}
}

func Test_UpdateUserDetails_Validate_Username_Invalid(t *testing.T) {
	username := "a"
	details := &UpdateUserDetails{Username: &username}
	err := details.Validate()
	if err != User_error_username_invalid {
		t.Fatalf("Unexpected error for username invalid: %#v", err)
	}
}

func Test_UpdateUserDetails_Validate_Emails_Invalid(t *testing.T) {
	details := &UpdateUserDetails{Emails: []string{"b@y.co", "c"}}
	err := details.Validate()
	if err != User_error_emails_invalid {
		t.Fatalf("Unexpected error for emails invalid: %#v", err)
	}
}

func Test_UpdateUserDetails_Validate_Password_Invalid(t *testing.T) {
	password := "1234567"
	details := &UpdateUserDetails{Password: &password}
	err := details.Validate()
	if err != User_error_new_password_invalid {
		t.Fatalf("Unexpected error for password invalid: %#v", err)
	}
}

func Test_UpdateUserDetails_Validate_Password_Invalid_CurrentPassword(t *testing.T) {
	currentPassword := "pwd"
	details := &UpdateUserDetails{CurrentPassword: &currentPassword}
	err := details.Validate()
	if err != User_error_current_password_invalid {
		t.Fatalf("Unexpected error for current password missing: %#v", err)
	}
}

func Test_UpdateUserDetails_Validate_Roles_Invalid(t *testing.T) {
	details := &UpdateUserDetails{Roles: []string{"invalid"}}
	err := details.Validate()
	if err != User_error_roles_invalid {
		t.Fatalf("Unexpected error for roles invalid: %#v", err)
	}
}

func Test_UpdateUserDetails_Validate_TermsAccepted_Invalid(t *testing.T) {
	termsAccepted := "2016-13-32T24:65:65-24:30"
	details := &UpdateUserDetails{TermsAccepted: &termsAccepted}
	err := details.Validate()
	if err != User_error_terms_accepted_invalid {
		t.Fatalf("Unexpected error for password invalid: %#v", err)
	}
}

func Test_UpdateUserDetails_Validate_Valid(t *testing.T) {
	username := "a@z.co"
	password := "12345678"
	currentPassword := "password"
	termsAccepted := "2016-01-01T12:00:00-08:00"
	emailVerified := true
	details := &UpdateUserDetails{
		Username:        &username,
		Emails:          []string{"b@y.co", "c@x.co"},
		Password:        &password,
		CurrentPassword: &currentPassword,
		Roles:           []string{"hcp"},
		TermsAccepted:   &termsAccepted,
		EmailVerified:   &emailVerified,
	}
	err := details.Validate()
	if err != nil {
		t.Fatalf("Unexpected error for valid: %#v", err)
	}
}

func Test_ParseUpdateUserDetails_InvalidJSON(t *testing.T) {
	source := ""
	details, err := ParseUpdateUserDetails(strings.NewReader(source))
	if err == nil {
		t.Fatalf("Unexpected success for invalid JSON")
	}
	if details != nil {
		t.Fatalf("Unexpected details for invalid JSON")
	}
}

func Test_ParseUpdateUserDetails_ValidAll(t *testing.T) {
	source := "{\"updates\": {\"username\": \"a@z.co\", \"emails\": [\"b@y.co\"], \"password\": \"12345678\", \"roles\": [\"hcp\"], \"termsAccepted\": \"2016-01-01T12:00:00-08:00\", \"emailVerified\": true}}"
	details, err := ParseUpdateUserDetails(strings.NewReader(source))
	if err != nil {
		t.Fatalf("Unexpected error for valid with all: %#v", err)
	}
	if details == nil {
		t.Fatalf("Missing details on success with all")
	}
	if *details.Username != "a@z.co" || !reflect.DeepEqual(details.Emails, []string{"b@y.co"}) || *details.Password != "12345678" || *details.TermsAccepted != "2016-01-01T12:00:00-08:00" || !*details.EmailVerified {
		t.Fatalf("Missing fields that should be present on success with all")
	}
}

func Test_User_Email(t *testing.T) {
	user := &User{Username: "a@z.co"}
	if user.Email() != "a@z.co" {
		t.Fatalf("Email returned incorrect username")
	}
}

func Test_User_Email_Missing(t *testing.T) {
	user := &User{}
	if user.Email() != "" {
		t.Fatalf("Email returned incorrect username")
	}
}
func Test_User_HasRole_Multiple(t *testing.T) {
	user := &User{Roles: []string{"hcp", "other"}}
	if !user.HasRole("hcp") {
		t.Fatalf("HasRole returned false when should have returned true")
	}
	if !user.HasRole("other") {
		t.Fatalf("HasRole returned false when should have returned true")
	}
	if user.HasRole("missing") {
		t.Fatalf("HasRole returned true when should have returned false")
	}
}

func Test_User_HasRole_One(t *testing.T) {
	user := &User{Roles: []string{"hcp"}}
	if !user.HasRole("hcp") {
		t.Fatalf("HasRole returned false when should have returned true")
	}
	if user.HasRole("missing") {
		t.Fatalf("HasRole returned true when should have returned false")
	}
}

func Test_User_HasRole_Empty(t *testing.T) {
	user := &User{Roles: []string{}}
	if user.HasRole("hcp") {
		t.Fatalf("HasRole returned true when should have returned false")
	}
	if user.HasRole("missing") {
		t.Fatalf("HasRole returned true when should have returned false")
	}
}

func Test_User_HasRole_Missing(t *testing.T) {
	user := &User{}
	if user.HasRole("hcp") {
		t.Fatalf("HasRole returned true when should have returned false")
	}
	if user.HasRole("missing") {
		t.Fatalf("HasRole returned true when should have returned false")
	}
}

func Test_User_IsClinic_Valid(t *testing.T) {
	user := &User{Roles: []string{"hcp"}}
	if !user.IsClinic() {
		t.Fatalf("IsClinic returned false when should have returned true")
	}
}

func Test_User_IsClinic_Invalid(t *testing.T) {
	user := &User{}
	if user.IsClinic() {
		t.Fatalf("IsClinic returned true when should have returned false")
	}
}

func Test_User_HashPassword(t *testing.T) {
	user := &User{Id: "123-user-id-you-know-me"}

	if err := user.HashPassword("my pw", "the salt"); err == nil {
		if user.PwHash == "" {
			t.Fatalf("the password should have been hashed")
		}
	} else {
		t.Fatalf("there should not have been an error")
	}
}

func Test_User_HashPassword_WithEmptyParams(t *testing.T) {
	user := &User{Id: "123-user-id-you-know-me"}

	if err := user.HashPassword("", ""); err == nil {
		t.Fatalf("there should be an error when the parameters are not passed")
	}

	if user.PwHash != "" {
		t.Fatalf("there was no password to hash so it should fail")
	}
}

func Test_User_PasswordsMatch_Match(t *testing.T) {
	user := &User{Id: "1234567890"}
	salt := "abc"
	err := user.HashPassword("3th3Hardw0y", salt)
	if err != nil {
		t.Fatalf("Failure hashing password")
	}
	if !user.PasswordsMatch("3th3Hardw0y", salt) {
		t.Fatalf("PasswordsMatch returned false when passwords match")
	}
}

func Test_User_PasswordsMatch_NoMatch_Case(t *testing.T) {
	user := &User{Id: "1234567890"}
	salt := "abc"
	err := user.HashPassword("3th3Hardw0y", salt)
	if err != nil {
		t.Fatalf("Failure hashing password")
	}
	if user.PasswordsMatch("3TH3HARDW0Y", salt) {
		t.Fatalf("PasswordsMatch returned true when passwords do not match")
	}
}

func Test_User_PasswordsMatch_NoMatch_MissingUserPassword(t *testing.T) {
	user := &User{Id: "1234567890"}
	salt := "abc"
	if user.PasswordsMatch("3th3Hardw0y", salt) {
		t.Fatalf("PasswordsMatch returned true when missing salt")
	}
}

func Test_User_PasswordsMatch_NoMatch_MissingQueryPassword(t *testing.T) {
	user := &User{Id: "1234567890"}
	salt := "abc"
	err := user.HashPassword("3th3Hardw0y", salt)
	if err != nil {
		t.Fatalf("Failure hashing password")
	}
	if user.PasswordsMatch("", salt) {
		t.Fatalf("PasswordsMatch returned true when missing query password")
	}
}

func Test_User_PasswordsMatch_NoMatch_MissingSalt(t *testing.T) {
	user := &User{Id: "1234567890"}
	salt := "abc"
	err := user.HashPassword("3th3Hardw0y", salt)
	if err != nil {
		t.Fatalf("Failure hashing password")
	}
	if user.PasswordsMatch("3th3Hardw0y", "") {
		t.Fatalf("PasswordsMatch returned true when missing salt")
	}
}

func Test_User_IsVerified(t *testing.T) {
	usernameWithSecret := "one@abc.com"
	passwordWithSecret := "3th3Hardw0y"
	userWithSecret, err := NewUser(&NewUserDetails{Username: &usernameWithSecret, Password: &passwordWithSecret, Emails: []string{"test+secret@foo.bar"}}, "some salt")
	if err != nil {
		t.Fatalf("Failure creating user with secret: %#v", err)
	}

	username := "two@abc.com"
	password := "3th3Hardw0y"
	user, err := NewUser(&NewUserDetails{Username: &username, Password: &password, Emails: []string{"test@foo.bar"}}, "some salt")
	if err != nil {
		t.Fatalf("Failure creating user: %#v", err)
	}

	//no secret
	if userWithSecret.IsEmailVerified("") == true {
		t.Fatalf("the user should not have been verified")
	}

	if user.IsEmailVerified("") == true {
		t.Fatalf("the user should not have been verified")
	}

	//with secret
	if userWithSecret.IsEmailVerified("+secret") == false {
		t.Fatalf("the user should say they are verified as we both have the secret")
	}

	if user.IsEmailVerified("+secret") == true {
		t.Fatalf("the user should say they are verified as they don't have the secret")
	}
}

func Test_User_DeepClone(t *testing.T) {
	user := &User{
		Id:            "1234567890",
		Username:      "a@b.co",
		Emails:        []string{"a@b.co", "c@d.co"},
		Roles:         []string{"hcp"},
		TermsAccepted: "2016-01-01T12:34:56-08:00",
		EmailVerified: true,
		PwHash:        "this-is-the-password-hash",
		Hash:          "this-is-the-hash",
		Private:       map[string]*IdHashPair{"a": &IdHashPair{"1", "2"}, "b": &IdHashPair{"3", "4"}},
	}
	clonedUser := user.DeepClone()
	if !reflect.DeepEqual(user, clonedUser) {
		t.Fatalf("The clone user is not exactly equal to the original user")
	}
}
