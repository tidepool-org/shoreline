package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type User struct {
	Id            string                 `json:"userid" bson:"userid,omitempty"` // map userid to id
	Name          string                 `json:"username" bson:"username"`
	Emails        []string               `json:"emails" bson:"emails"`
	Roles         []string               `json:"roles" bson:"roles"`
	TermsAccepted string                 `json:"termsAccepted" bson:"termsAccepted"`
	Verified      bool                   `json:"emailVerified" bson:"authenticated"` //tag is name `authenticated` for historical reasons
	PwHash        string                 `json:"-" bson:"pwhash"`
	Hash          string                 `json:"-" bson:"userhash"`
	Private       map[string]*IdHashPair `json:"-" bson:"private"`
}

/*
 * Incoming user details used to create or update a `User`
 */
type UserDetail struct {
	Id            string   //no tag as we aren't getting it from json
	Name          string   `json:"username"`
	Emails        []string `json:"emails"`
	Roles         []string `json:"roles"`
	TermsAccepted string   `json:"termsAccepted"`
	Pw            string   `json:"password"`
	Verified      bool     `json:"authenticated"` //tag is name `authenticated` for historical reasons
}

const (
	//predefined roles that tidepool will understand
	CLINIC_ROLE = "clinic"
)

var (
	User_error_name_pw_required = errors.New("User: both the name and pw are required")
	User_error_no_details_given = errors.New("User: no user details were sent")
	User_error_invalid_role     = errors.New("User: trying to set the role as")
	AllowedUserRoles            = map[string]string{
		CLINIC_ROLE: CLINIC_ROLE,
	}
)

func ValidateUserRoles(roles []string) error {
	for i := range roles {
		if _, ok := AllowedUserRoles[roles[i]]; !ok {
			configuredRoles := []string{}
			for k := range AllowedUserRoles {
				configuredRoles = append(configuredRoles, k)
			}
			return errors.New(fmt.Sprintf("User: trying to set role as `%s` which is not one of the valid roles `%s`", roles[i], configuredRoles))
		}
	}
	return nil
}

func NewUser(details *UserDetail, salt string) (user *User, err error) {

	if details.Name == "" || details.Pw == "" {
		return nil, User_error_name_pw_required
	}

	details.Name = strings.ToLower(details.Name)

	id, err := generateUniqueHash([]string{details.Name, details.Pw}, 10)
	if err != nil {
		return nil, errors.New("User: error generating id")
	}
	hash, err := generateUniqueHash([]string{details.Name, details.Pw, id}, 24)
	if err != nil {
		return nil, errors.New("User: error generating hash")
	}
	pwHash, err := GeneratePasswordHash(id, details.Pw, salt)
	if err != nil {
		return nil, errors.New("User: error generating password hash")
	}
	return &User{Id: id, Name: details.Name, Emails: details.Emails, Hash: hash, PwHash: pwHash, Verified: false}, nil
}

//Child Account are linked to another users account and don't require a password or emails
func NewChildUser(details *UserDetail, salt string) (user *User, err error) {

	//name hashed from the `nice` name you gave us
	name, err := generateUniqueHash([]string{details.Name, time.Now().String()}, 10)
	if err != nil {
		return nil, errors.New("User: error generating id")
	}
	id, err := generateUniqueHash([]string{name}, 10)
	if err != nil {
		return nil, errors.New("User: error generating hash")
	}
	hash, err := generateUniqueHash([]string{name, id}, 24)
	if err != nil {
		return nil, errors.New("User: error generating password hash")
	}

	return &User{Id: id, Name: name, Emails: details.Emails, Hash: hash, Verified: true, TermsAccepted: details.TermsAccepted}, nil
}

func UserFromDetails(details *UserDetail) (user *User) {
	return &User{Id: details.Id, Name: strings.ToLower(details.Name), Emails: details.Emails, Roles: details.Roles, TermsAccepted: details.TermsAccepted}
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

func getUserDetail(req *http.Request) (ud *UserDetail, err error) {
	if req.ContentLength > 0 {
		if err := json.NewDecoder(req.Body).Decode(&ud); err != nil {
			return nil, err
		}
		return ud, nil
	}
	return nil, User_error_no_details_given
}
