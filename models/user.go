package models

import (
	"errors"
	"strings"
)

type User struct {
	Id      string                 `json:"userid"   bson:"userid,omitempty"` // map userid to id
	Name    string                 `json:"username" bson:"username"`
	Emails  []string               `json:"emails" 	bson:"emails"`
	Pw      string                 `json:"-"` //json:"-" is used to prevent the field being serialised to json
	PwHash  string                 `json:"-" 		bson:"pwhash"`
	Hash    string                 `json:"-" 		bson:"userhash"`
	Private map[string]*IdHashPair `json:"-" 		bson:"private"`
}

/*
 * Incoming user details used to create or update a `User`
 */
type UserDetail struct {
	Id     string   //no tag as we aren't getting it from json
	Name   string   `json:"username"`
	Emails []string `json:"emails"`
	Pw     string   `json:"password"`
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

	return &User{Id: id, Name: details.Name, Emails: details.Emails, Hash: hash, PwHash: pwHash}, nil
}

func UserFromDetails(details *UserDetail) (user *User) {

	return &User{Id: details.Id, Name: strings.ToLower(details.Name), Emails: details.Emails, Pw: details.Pw}
}

func (u *User) HashPassword(pw, salt string) (err error) {
	u.PwHash, err = GeneratePasswordHash(u.Id, pw, salt)
	return err
}

func (u *User) NamesMatch(name string) bool {
	return strings.ToLower(u.Name) == strings.ToLower(name)
}

func (u *User) PwsMatch(usrToCheck *User, salt string) bool {

	if usrToCheck.Pw != "" {
		pwMatch, _ := GeneratePasswordHash(u.Id, usrToCheck.Pw, salt)
		return u.PwHash == pwMatch
	}
	return false
}
