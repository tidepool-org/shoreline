package models

import (
	"bytes"
	"html/template"
	"time"
)

const (
	PW_RESET        = "password_reset"
	CARETEAM_INVITE = "careteam_invitation"
	CONFIRMATION    = "email_confirmation"
)

type (
	Email struct {
		Key      string
		Content  string
		Type     string //e.g. PW_RESET, CARETEAM_INVITE ...
		ToUser   string
		FromUser string    // could be empty
		Created  time.Time //used for expiry
		Sent     time.Time //sent - or maybe failed
	}

	ResetEmail struct {
		Name string
		Link string
	}

	CareTeamEmail struct {
		Name string
		Team string
		Link string
	}
)

func NewCareteamInviteEmail(to *User, from *User, templatedText string) (*Email, error) {

	compiled := template.Must(template.New(CARETEAM_INVITE).Parse(templatedText))
	created := time.Now()
	keyHash, _ := generateUniqueHash([]string{CARETEAM_INVITE, to.Id, created.String()}, 24)
	key := "invite/" + keyHash

	inviteEmail := &CareTeamEmail{Name: to.Name, Team: from.Name, Link: key}

	email := &Email{Key: key, Type: CARETEAM_INVITE, ToUser: to.Id, FromUser: from.Id, Created: created}

	var buffer bytes.Buffer

	if err := compiled.Execute(&buffer, inviteEmail); err != nil {
		return nil, err
	}

	parsedTemplate := buffer.String()

	email.Content = parsedTemplate
	return email, nil
}

func NewPwResetEmail(u *User, templatedText string) (*Email, error) {

	compiled := template.Must(template.New(PW_RESET).Parse(templatedText))
	created := time.Now()
	keyHash, _ := generateUniqueHash([]string{PW_RESET, u.Id, created.String()}, 24)
	key := "reset/" + keyHash

	resetEmail := &ResetEmail{Name: u.Name, Link: key}

	email := &Email{Key: key, Type: PW_RESET, ToUser: u.Id, Created: created}

	var buffer bytes.Buffer

	if err := compiled.Execute(&buffer, resetEmail); err != nil {
		return nil, err
	}

	parsedTemplate := buffer.String()

	email.Content = parsedTemplate
	return email, nil
}

func (e *Email) Send() {
	e.Sent = time.Now()
}
