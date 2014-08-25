package models

import (
	//"html/template"
	"time"
)

const (
	PWRESET  = "reset"
	INVITE   = "invite"
	CARETEAM = "cteam"
)

type (
	Email struct {
		Content  string
		Type     string //e.g. pwreset, invite ....
		ToUser   string
		FromUser string    // could be null
		Created  time.Time //used for expiry
		Sent     time.Time //sent - or maybe failed
	}
)

func NewPwResetEmail(u *User, templatedText string) *Email {

	/*const letter = `
	Dear {{.Name}},
	{{if .Attended}}
	It was a pleasure to see you at the wedding.{{else}}
	It is a shame you couldn't make it to the wedding.{{end}}
	{{with .Gift}}Thank you for the lovely {{.}}.
	{{end}}
	Best wishes,
	Josie
	`*/

	return &Email{Content: templatedText, Type: PWRESET, ToUser: u.Id, Created: time.Now()}
}

func (e *Email) Send() {
	e.Sent = time.Now()
}
