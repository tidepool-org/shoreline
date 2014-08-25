package models

import (
	"testing"
)

var (
	EMAIL_USER     = &User{Id: "123-99-100", Name: "Test Emails", Emails: []string{"test@new.bar"}}
	EMAIL_TEMPLATE = "Hi %s\n\nLooks like you have forgotton your password, click the link below to reset it\n\n%s\n\nThanks\nThe Tidepool Team"
)

func TestEmail(t *testing.T) {

	email := NewPwResetEmail(EMAIL_USER, EMAIL_TEMPLATE)

	if email.ToUser != EMAIL_USER.Id {
		t.Fatal("the user being emailed should be set")
	}

	if email.Content == "" {
		t.Fatal("the content of the email should be set")
	}

	if email.Created.IsZero() {
		t.Fatal("the date the email was created should be set")
	}

}

func TestEmailSend(t *testing.T) {

	email := NewPwResetEmail(EMAIL_USER, EMAIL_TEMPLATE)

	if email.Sent.IsZero() == false {
		t.Fatal("the time sent should not be set")
	}

	email.Send()

	if email.Sent.IsZero() {
		t.Fatal("the time sent should have been set")
	}

}
