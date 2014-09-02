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
)

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
