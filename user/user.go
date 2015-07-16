package user

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
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

func NewUser(details *UserDetail, salt string) (*User, error) {

	if details.Name == "" || details.Pw == "" {
		return nil, errors.New("both the name and pw are required")
	}
	//name is always lowercase
	details.Name = strings.ToLower(details.Name)
	//generate the hashes
	id, err := generateUniqueHash([]string{details.Name, details.Pw}, 10)
	if err != nil {
		return nil, err
	}
	hash, err := generateUniqueHash([]string{details.Name, details.Pw, id}, 24)
	if err != nil {
		return nil, err
	}
	pwHash, err := GeneratePasswordHash(id, details.Pw, salt)
	if err != nil {
		return nil, err
	}
	//all good we have a user
	return &User{Id: id, Name: details.Name, Emails: details.Emails, Hash: hash, PwHash: pwHash, Verified: false}, nil
}

//Child Account are linked to another users account and don't require a password or emails
func NewChildUser(details *UserDetail, salt string) (*User, error) {

	if details.Name == "" {
		return nil, errors.New("name is required")
	}

	//name hashed from the `nice` name you gave us
	name, err := generateUniqueHash([]string{details.Name, time.Now().String()}, 10)
	if err != nil {
		return nil, err
	}
	id, err := generateUniqueHash([]string{name}, 10)
	if err != nil {
		return nil, err
	}
	hash, err := generateUniqueHash([]string{name, id}, 24)
	if err != nil {
		return nil, err
	}

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

func (u *User) IsVerified(secret string) bool {
	//allows override for dev and test purposes
	if secret != "" {
		for i := range u.Emails {
			if strings.Contains(u.Emails[i], secret) {
				return true
			}
		}
	}
	return u.Verified
}

func getUserDetail(req *http.Request) (ud *UserDetail) {
	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&ud); err != nil {
			log.Print(USER_API_PREFIX, "error trying to decode user detail ", err)
			return ud
		}
	}
	log.Printf(USER_API_PREFIX+"User details [%v]", ud)
	return ud
}
