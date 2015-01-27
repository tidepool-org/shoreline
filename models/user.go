package models

import (
	"errors"
	"strings"
	"time"
)

type User struct {
	Id       string                 `json:"userid" bson:"userid,omitempty"` // map userid to id
	Name     string                 `json:"username" bson:"username"`
	Emails   []string               `json:"emails" bson:"emails"`
	Verified bool                   `json:"-" bson:"authenticated"` //tag is name `authenticated` for historical reasons
	PwHash   string                 `json:"-" bson:"pwhash"`
	Hash     string                 `json:"-" bson:"userhash"`
	Private  map[string]*IdHashPair `json:"-" bson:"private"`
}

/*
 * Incoming user details used to create or update a `User`
 */
type UserDetail struct {
	Id       string   //no tag as we aren't getting it from json
	Name     string   `json:"username"`
	Emails   []string `json:"emails"`
	Pw       string   `json:"password"`
	Verified bool     `json:"authenticated"` //tag is name `authenticated` for historical reasons
}

func NewUser(details *UserDetail, salt string) (user *User, err error) {

	if details.Name == "" || details.Pw == "" {
		return user, errors.New("both the name and pw are required")
	}
	//name is always lowercase
	details.Name = strings.ToLower(details.Name)

	id, _ := generateUniqueHash([]string{details.Name, details.Pw}, 10)
	hash, _ := generateUniqueHash([]string{details.Name, details.Pw, id}, 24)
	pwHash, _ := GeneratePasswordHash(id, details.Pw, salt)

	return &User{Id: id, Name: details.Name, Emails: details.Emails, Hash: hash, PwHash: pwHash, Verified: false}, nil
}

//Child Account are linked to another users account and don't require a password or emails
func NewChildUser(details *UserDetail, salt string) (user *User, err error) {

	//name hashed from the `nice` name you gave us
	name, _ := generateUniqueHash([]string{details.Name, time.Now().String()}, 10)
	id, _ := generateUniqueHash([]string{name}, 10)
	hash, _ := generateUniqueHash([]string{name, id}, 24)

	return &User{Id: id, Name: name, Emails: details.Emails, Hash: hash, Verified: true}, nil
}

func UserFromDetails(details *UserDetail) (user *User) {
	return &User{Id: details.Id, Name: strings.ToLower(details.Name), Emails: details.Emails}
}

func (u *User) HashPassword(pw, salt string) (err error) {
	u.PwHash, err = GeneratePasswordHash(u.Id, pw, salt)
	return err
}

func (u *User) NamesMatch(name string) bool {
	return strings.ToLower(u.Name) == strings.ToLower(name)
}

func (u *User) PwsMatch(pw, salt string) bool {
	if pw != "" {
		pwMatch, _ := GeneratePasswordHash(u.Id, pw, salt)
		return u.PwHash == pwMatch
	}
	return false
}

func (u *User) IsVerified(canSkip bool, secret string) bool {
	//allows override for dev and test purposes
	if canSkip && secret != "" {
		for i := range u.Emails {
			if strings.Contains(u.Emails[i], secret) {
				return true
			}
		}
		return false
	}
	return u.Verified
}
