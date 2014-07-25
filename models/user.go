package models

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
)

type User struct {
	Id      string                `json:"userid" 	bson:"_id,omitempty"` // map _id to id
	Name    string                `json:"username" 	bson:"name"`
	Emails  []string              `json:"emails" 	bson:"emails"`
	Pw      string                `json:"password"`
	PwHash  string                `json:"-" 		bson:"pwhash"` //json:"-" is used to prevent the pwhash from being serialised to json
	Hash    string                `json:"-" 		bson:"hash"`
	Private map[string]IdHashPair `json:"-" 		bson:"private"`
}

func NewUser(name, pw string, emails []string) (user *User, err error) {

	if name == "" || pw == "" {
		return user, errors.New("both the name and pw are required")
	}
	id, _ := generateUniqueHash([]string{name, pw}, 10)
	hash, _ := generateUniqueHash([]string{name, pw, id}, 24)
	return &User{Id: id, Name: name, Emails: emails, Hash: hash}, nil
}

func (u *User) HasIdentifier() bool {
	return u.Name != "" || u.Id != "" || len(u.Emails) > 0
}

func (u *User) CanUpdate() bool {
	return u.Name != "" || u.Id != "" || len(u.Emails) > 0
}

func (u *User) HashPassword(pw, salt string) error {

	if pw == "" || salt == "" {
		return errors.New("both the pw and salt are required")
	}

	hash := sha1.New()
	hash.Write([]byte(pw))
	hash.Write([]byte(salt))
	hash.Write([]byte(u.Id))
	u.PwHash = hex.EncodeToString(hash.Sum(nil))

	return nil
}
