package models

import (
	"bytes"
	"html/template"
	"log"
	"strings"
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
		ToUser   *User
		FromUser *User     // could be empty
		Created  time.Time //used for expiry
		Sent     time.Time //sent - or maybe failed
	}

	EmailTemplate struct {
		PasswordReset  string `json:"passwordReset"`
		CareteamInvite string `json:"careteamInvite"`
		Confirmation   string `json:"confirmation"`
	}
)

func NewEmail(emailType string, cfg *EmailTemplate, usr ...*User) (*Email, error) {

	created := time.Now()

	email := &Email{
		Key:     generateKey(emailType, usr[0].Id, created.String()),
		ToUser:  usr[0],
		Created: created,
	}

	if len(usr) > 1 {
		email.FromUser = usr[1]
	}

	email.Content = parseTemplateContent(
		loadTemplate(emailType, cfg),
		email,
	)

	return email, nil
}

/*
 * Load the correct compiled template
 */
func loadTemplate(emailType string, cfg *EmailTemplate) *template.Template {

	var compiled *template.Template

	switch {
	case strings.Index(strings.ToLower(emailType), CARETEAM_INVITE) != -1:
		compiled = template.Must(template.New(CARETEAM_INVITE).Parse(cfg.CareteamInvite))
		break
	case strings.Index(strings.ToLower(emailType), CONFIRMATION) != -1:
		compiled = template.Must(template.New(CONFIRMATION).Parse(cfg.Confirmation))
		break
	case strings.Index(strings.ToLower(emailType), PW_RESET) != -1:
		compiled = template.Must(template.New(PW_RESET).Parse(cfg.PasswordReset))
		break
	default:
		log.Println("Unknown type ", emailType)
		compiled = nil
		break
	}

	return compiled
}

/*
 * Parse the content into the template
 */
func parseTemplateContent(compiled *template.Template, content interface{}) string {
	var buffer bytes.Buffer

	if err := compiled.Execute(&buffer, content); err != nil {
		log.Println("error parsing template ", err)
		return ""
	}
	return buffer.String()
}

/*
 * Generate the unique key used in the URL
 */
func generateKey(emailType, address, created string) string {
	keyHash, _ := generateUniqueHash([]string{emailType, address, created}, 24)
	return emailType + "/" + keyHash
}

/*func NewCareteamInviteEmail(to *User, from *User, templatedText string) (*Email, error) {

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
}*/

func (e *Email) Send() {
	e.Sent = time.Now()
}
