package models

import (
	"errors"
)

type User struct {
	Id      string                 `json:"userid" 	bson:"_id,omitempty"` // map _id to id
	Name    string                 `json:"username" bson:"name"`
	Emails  []string               `json:"emails" 	bson:"emails"`
	Pw      string                 `json:"-"`
	PwHash  string                 `json:"-" 		bson:"pwhash"` //json:"-" is used to prevent the pwhash from being serialised to json
	Hash    string                 `json:"-" 		bson:"hash"`
	Private map[string]*IdHashPair `json:"-" 		bson:"private"`
}

/*
 * Incoming user details used to create or update a `User`
 */
type UserDetail struct {
	Name   string   `json:"username"`
	Emails []string `json:"emails"`
	Pw     string   `json:"password"`
}

func NewUser(details *UserDetail, salt string) (user *User, err error) {

	if details.Name == "" || details.Pw == "" {
		return user, errors.New("both the name and pw are required")
	}
	id, _ := generateUniqueHash([]string{details.Name, details.Pw}, 10)
	hash, _ := generateUniqueHash([]string{details.Name, details.Pw, id}, 24)
	pwHash, _ := GeneratePasswordHash(id, details.Pw, salt)

	return &User{Id: id, Name: details.Name, Emails: details.Emails, Hash: hash, PwHash: pwHash}, nil
}

func (u *User) HasIdentifier() bool {
	return u.Name != "" || u.Id != "" || len(u.Emails) > 0
}

func (u *User) CanUpdate() bool {
	return u.Name != "" || u.Id != "" || len(u.Emails) > 0
}

func (u *User) HashPassword(pw, salt string) (err error) {
	u.PwHash, err = GeneratePasswordHash(u.Id, pw, salt)
	return err
}

func (u *User) HasPwMatch(usrToCheck *User, salt string) bool {

	if usrToCheck.Pw != "" {
		pwMatch, _ := GeneratePasswordHash(u.Id, usrToCheck.Pw, salt)
		return u.PwHash == pwMatch
	}
	return false
}
