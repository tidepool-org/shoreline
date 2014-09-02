package models

import (
	"strings"
	"testing"
)

var (
	EMAIL_USER = &User{Id: "123-99-100", Name: "To User", Emails: []string{"to@new.bar"}}
	FROM_USER  = &User{Id: "456-99-100", Name: "From user", Emails: []string{"from@new.bar"}}

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

	InviteTemplate = `
{{define "invite_test"}}
## Test Template

{{ .Name }}
...
{{ .Link }}
...
{{ .Team }}
...

{{end}}

{{template "invite_test" .}}
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

func TestEmail_CareteamInvite(t *testing.T) {

	email, err := NewCareteamInviteEmail(EMAIL_USER, FROM_USER, InviteTemplate)

	if err != nil {
		t.Fatalf("unexpected error ", err)
	}

	if email.ToUser != EMAIL_USER.Id {
		t.Fatal("the user being emailed should be set")
	}

	if email.FromUser != FROM_USER.Id {
		t.Fatal("the from user being emailed should be set")
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

	if strings.Contains(email.Content, FROM_USER.Name) == false {
		t.Fatal("the team should be used")
	}

	if email.Key == "" {
		t.Fatal("the content of the email should be set")
	}

	if email.Type != CARETEAM_INVITE {
		t.Fatal("the type should be ", CARETEAM_INVITE)
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
