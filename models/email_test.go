package models

import (
	"strings"
	"testing"
)

var (
	EMAIL_USER = &User{Id: "123-99-100", Name: "Test Emails", Emails: []string{"test@new.bar"}}

	ResetTemplate = `
{{define "reset_test"}}
## Test Template

Hi {{ .Name }}
...
{{ .Link }}
...

{{end}}

{{template "reset_test" .}}
`
)

func TestEmail_PwReset(t *testing.T) {

	email, err := NewPwResetEmail(EMAIL_USER, ResetTemplate)

	if err != nil {
		t.Fatalf("unexpected error ", err)
	}

	if email.ToUser != EMAIL_USER.Id {
		t.Fatal("the user being emailed should be set")
	}

	if email.Content == "" {
		t.Fatal("the content of the email should be set")
	}

	if strings.Contains(email.Content, EMAIL_USER.Name) == false {
		t.Fatal("the name should be set")
	}

	if strings.Contains(email.Content, email.Key) == false {
		t.Fatal("the key should be used")
	}

	if email.Key == "" {
		t.Fatal("the content of the email should be set")
	}

	if email.FromUser != "" {
		t.Fatal("the FromUser should be empty")
	}

	if email.Type != PW_RESET {
		t.Fatal("the type should be ", PW_RESET)
	}

	if email.Created.IsZero() {
		t.Fatal("the date the email was created should be set")
	}

}

func TestEmailSend(t *testing.T) {

	email, _ := NewPwResetEmail(EMAIL_USER, ResetTemplate)

	if email.Sent.IsZero() == false {
		t.Fatal("the time sent should not be set")
	}

	email.Send()

	if email.Sent.IsZero() {
		t.Fatal("the time sent should have been set")
	}

}
