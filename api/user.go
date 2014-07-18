package api

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

type User struct {
	Id     string   `json:"id" bson:"_id,omitempty"` // map _id to id
	Name   string   `json:"name" bson:"name"`
	Emails []string `json:"emails" bson:"emails"`
	PwHash string   `json:"-" bson:"pwhash"` //json:"-" is used to prevent the pwhash from being serialised to json
	Hash   string   `json:"hash" bson:"hash"`
}

func NewUser(name, pw string, emails []string) (*User, error) {

	if name == "" || pw == "" {
		return &User{}, errors.New("both the name and pw are required")
	}

	id, _ := generateUniqueHash([]string{name, pw}, 10)
	hash, _ := generateUniqueHash([]string{name, pw, id}, 24)
	return &User{Id: id, Name: name, Emails: emails, Hash: hash}, nil
}

func (u *User) HasIdentifier() bool {
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

func generateUniqueHash(strings []string, length int) (string, error) {

	if len(strings) > 0 && length > 0 {

		hash := sha1.New()

		for i := range strings {
			hash.Write([]byte(strings[i]))
		}

		hash.Write([]byte(strconv.FormatInt(time.Now().Unix(), 10)))
		//delay just a bit to make sure that we have move on in time
		time.Sleep(1 * time.Millisecond)
		hashString := hex.EncodeToString(hash.Sum(nil))

		return string([]rune(hashString)[0:length]), nil
	}

	return "", errors.New("both strings and length are required")

}
