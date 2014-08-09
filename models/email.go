package models

import (
	"fmt"
	"time"
)

type (
	Email struct {
		Content string
		User    *User
		Created time.Time
		Sent    time.Time
	}
)

func NewPwResetEmail(u *User, templatedText string) *Email {
	content := fmt.Sprintf(templatedText, u.Name)
	return &Email{Content: content, User: u, Created: time.Now()}
}

func (e *Email) Send() {
	e.Sent = time.Now()
}
