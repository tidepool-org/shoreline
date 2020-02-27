package user

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

type User struct {
	Id             string                 `json:"userid,omitempty" bson:"userid,omitempty"` // map userid to id
	Username       string                 `json:"username,omitempty" bson:"username,omitempty"`
	Emails         []string               `json:"emails,omitempty" bson:"emails,omitempty"`
	Roles          []string               `json:"roles,omitempty" bson:"roles,omitempty"`
	TermsAccepted  string                 `json:"termsAccepted,omitempty" bson:"termsAccepted,omitempty"`
	EmailVerified  bool                   `json:"emailVerified" bson:"authenticated"` //tag is name `authenticated` for historical reasons
	PwHash         string                 `json:"-" bson:"pwhash,omitempty"`
	Hash           string                 `json:"-" bson:"userhash,omitempty"`
	Private        map[string]*IdHashPair `json:"-" bson:"private"`
	FailedLogin    *FailedLoginInfos      `json:"-" bson:"failedLogin,omitempty"`
	CreatedTime    string                 `json:"createdTime,omitempty" bson:"createdTime,omitempty"`
	CreatedUserID  string                 `json:"createdUserId,omitempty" bson:"createdUserId,omitempty"`
	ModifiedTime   string                 `json:"modifiedTime,omitempty" bson:"modifiedTime,omitempty"`
	ModifiedUserID string                 `json:"modifiedUserId,omitempty" bson:"modifiedUserId,omitempty"`
	DeletedTime    string                 `json:"deletedTime,omitempty" bson:"deletedTime,omitempty"`
	DeletedUserID  string                 `json:"deletedUserId,omitempty" bson:"deletedUserId,omitempty"`
}

// FailedLoginInfos monitor the failed login of an user account.
type FailedLoginInfos struct {
	// Count is the current number of failed login since previous success (reset to 0 after each successful login)
	Count int `json:"-" bson:"count"`
	// Total number of failed login attempt (this value is never reset to 0)
	Total int `json:"-" bson:"total"`
	// Next time we may consider a valid login attempt on this account
	NextLoginAttemptTime string `json:"-" bson:"nextLoginAttemptTime,omitempty"`
}

/*
 * Incoming user details used to create or update a `User`
 */
type NewUserDetails struct {
	Username *string
	Emails   []string
	Password *string
	Roles    []string
}

type NewCustodialUserDetails struct {
	Username *string
	Emails   []string
}

type UpdateUserDetails struct {
	Username      *string
	Emails        []string
	Password      *string
	Roles         []string
	TermsAccepted *string
	EmailVerified *bool
}

var (
	User_error_details_missing        = errors.New("User details are missing")
	User_error_username_missing       = errors.New("Username is missing")
	User_error_username_invalid       = errors.New("Username is invalid")
	User_error_emails_missing         = errors.New("Emails are missing")
	User_error_emails_invalid         = errors.New("Emails are invalid")
	User_error_password_missing       = errors.New("Password is missing")
	User_error_password_invalid       = errors.New("Password is invalid")
	User_error_roles_invalid          = errors.New("Roles are invalid")
	User_error_terms_accepted_invalid = errors.New("Terms accepted is invalid")
	User_error_email_verified_invalid = errors.New("Email verified is invalid")
)

func ExtractBool(data map[string]interface{}, key string) (*bool, bool) {
	if raw, ok := data[key]; !ok {
		return nil, true
	} else if extractedBool, ok := raw.(bool); !ok {
		return nil, false
	} else {
		return &extractedBool, true
	}
}

func ExtractString(data map[string]interface{}, key string) (*string, bool) {
	if raw, ok := data[key]; !ok {
		return nil, true
	} else if extractedString, ok := raw.(string); !ok {
		return nil, false
	} else {
		return &extractedString, true
	}
}

func ExtractArray(data map[string]interface{}, key string) ([]interface{}, bool) {
	if raw, ok := data[key]; !ok {
		return nil, true
	} else if extractedArray, ok := raw.([]interface{}); !ok {
		return nil, false
	} else if len(extractedArray) == 0 {
		return []interface{}{}, true
	} else {
		return extractedArray, true
	}
}

func ExtractStringArray(data map[string]interface{}, key string) ([]string, bool) {
	if rawArray, ok := ExtractArray(data, key); !ok {
		return nil, false
	} else if rawArray == nil {
		return nil, true
	} else {
		extractedStringArray := make([]string, 0)
		for _, raw := range rawArray {
			if extractedString, ok := raw.(string); !ok {
				return nil, false
			} else {
				extractedStringArray = append(extractedStringArray, extractedString)
			}
		}
		return extractedStringArray, true
	}
}

func ExtractStringMap(data map[string]interface{}, key string) (map[string]interface{}, bool) {
	if raw, ok := data[key]; !ok {
		return nil, true
	} else if extractedMap, ok := raw.(map[string]interface{}); !ok {
		return nil, false
	} else if len(extractedMap) == 0 {
		return map[string]interface{}{}, true
	} else {
		return extractedMap, true
	}
}

func IsValidEmail(email string) bool {
	ok, _ := regexp.MatchString(`\A(?i)([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})\z`, email)
	return ok
}

func IsValidPassword(password string) bool {
	ok, _ := regexp.MatchString(`\A\S{8,72}\z`, password)
	return ok
}

func IsValidRole(role string) bool {
	switch role {
	case "clinic":
		return true
	default:
		return false
	}
}

func IsValidDate(date string) bool {
	_, err := time.Parse("2006-01-02", date)
	return err == nil
}

func IsValidTimestamp(timestamp string) bool {
	_, err := time.Parse("2006-01-02T15:04:05-07:00", timestamp)
	return err == nil
}

func (details *NewUserDetails) ExtractFromJSON(reader io.Reader) error {
	if reader == nil {
		return User_error_details_missing
	}

	var decoded map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&decoded); err != nil {
		return err
	}

	var (
		username *string
		emails   []string
		password *string
		roles    []string
		ok       bool
	)

	if username, ok = ExtractString(decoded, "username"); !ok {
		return User_error_username_invalid
	}
	if emails, ok = ExtractStringArray(decoded, "emails"); !ok {
		return User_error_emails_invalid
	}
	if password, ok = ExtractString(decoded, "password"); !ok {
		return User_error_password_invalid
	}
	if roles, ok = ExtractStringArray(decoded, "roles"); !ok {
		return User_error_roles_invalid
	}

	details.Username = username
	details.Emails = emails
	details.Password = password
	details.Roles = roles
	return nil
}

func (details *NewUserDetails) Validate() error {
	if details.Username == nil {
		return User_error_username_missing
	} else if !IsValidEmail(*details.Username) {
		return User_error_username_invalid
	}

	if len(details.Emails) == 0 {
		return User_error_emails_missing
	} else {
		for _, email := range details.Emails {
			if !IsValidEmail(email) {
				return User_error_emails_invalid
			}
		}
	}

	if details.Password == nil {
		return User_error_password_missing
	} else if !IsValidPassword(*details.Password) {
		return User_error_password_invalid
	}

	if details.Roles != nil {
		for _, role := range details.Roles {
			if !IsValidRole(role) {
				return User_error_roles_invalid
			}
		}
	}

	return nil
}

func ParseNewUserDetails(reader io.Reader) (*NewUserDetails, error) {
	details := &NewUserDetails{}
	if err := details.ExtractFromJSON(reader); err != nil {
		return nil, err
	} else {
		return details, nil
	}
}

func NewUser(details *NewUserDetails, salt string) (user *User, err error) {
	if details == nil {
		return nil, errors.New("New user details is nil")
	} else if err := details.Validate(); err != nil {
		return nil, err
	}

	user = &User{Username: *details.Username, Emails: details.Emails, Roles: details.Roles}

	if user.Id, err = generateUniqueHash([]string{*details.Username, *details.Password}, 10); err != nil {
		return nil, errors.New("User: error generating id")
	}
	if user.Hash, err = generateUniqueHash([]string{*details.Username, *details.Password, user.Id}, 24); err != nil {
		return nil, errors.New("User: error generating hash")
	}

	if err = user.HashPassword(*details.Password, salt); err != nil {
		return nil, errors.New("User: error generating password hash")
	}

	return user, nil
}

func (details *NewCustodialUserDetails) ExtractFromJSON(reader io.Reader) error {
	if reader == nil {
		return User_error_details_missing
	}

	var decoded map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&decoded); err != nil {
		return err
	}

	var (
		username *string
		emails   []string
		ok       bool
	)

	if username, ok = ExtractString(decoded, "username"); !ok {
		return User_error_username_invalid
	}
	if emails, ok = ExtractStringArray(decoded, "emails"); !ok {
		return User_error_emails_invalid
	}

	details.Username = username
	details.Emails = emails
	return nil
}

func (details *NewCustodialUserDetails) Validate() error {
	if details.Username != nil {
		if !IsValidEmail(*details.Username) {
			return User_error_username_invalid
		}
	}

	if details.Emails != nil {
		for _, email := range details.Emails {
			if !IsValidEmail(email) {
				return User_error_emails_invalid
			}
		}
	}

	return nil
}

func ParseNewCustodialUserDetails(reader io.Reader) (*NewCustodialUserDetails, error) {
	details := &NewCustodialUserDetails{}
	if err := details.ExtractFromJSON(reader); err != nil {
		return nil, err
	} else {
		return details, nil
	}
}

func NewCustodialUser(details *NewCustodialUserDetails, salt string) (user *User, err error) {
	if details == nil {
		return nil, errors.New("New custodial user details is nil")
	} else if err := details.Validate(); err != nil {
		return nil, err
	}

	var username string
	if details.Username != nil {
		username = *details.Username
	}

	user = &User{Username: username, Emails: details.Emails}

	if user.Id, err = generateUniqueHash([]string{username}, 10); err != nil {
		return nil, errors.New("User: error generating id")
	}
	if user.Hash, err = generateUniqueHash([]string{username, user.Id}, 24); err != nil {
		return nil, errors.New("User: error generating hash")
	}

	return user, nil
}

func (details *UpdateUserDetails) ExtractFromJSON(reader io.Reader) error {
	if reader == nil {
		return User_error_details_missing
	}

	var decoded map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&decoded); err != nil {
		return err
	}

	var (
		username      *string
		emails        []string
		password      *string
		roles         []string
		termsAccepted *string
		emailVerified *bool
		ok            bool
	)

	decoded, ok = ExtractStringMap(decoded, "updates")
	if !ok || decoded == nil {
		return User_error_details_missing
	}

	if username, ok = ExtractString(decoded, "username"); !ok {
		return User_error_username_invalid
	}
	if emails, ok = ExtractStringArray(decoded, "emails"); !ok {
		return User_error_emails_invalid
	}
	if password, ok = ExtractString(decoded, "password"); !ok {
		return User_error_password_invalid
	}
	if roles, ok = ExtractStringArray(decoded, "roles"); !ok {
		return User_error_roles_invalid
	}
	if termsAccepted, ok = ExtractString(decoded, "termsAccepted"); !ok {
		return User_error_terms_accepted_invalid
	}
	if emailVerified, ok = ExtractBool(decoded, "emailVerified"); !ok {
		return User_error_email_verified_invalid
	}

	details.Username = username
	details.Emails = emails
	details.Password = password
	details.Roles = roles
	details.TermsAccepted = termsAccepted
	details.EmailVerified = emailVerified
	return nil
}

func (details *UpdateUserDetails) Validate() error {
	if details.Username != nil {
		if !IsValidEmail(*details.Username) {
			return User_error_username_invalid
		}
	}

	if details.Emails != nil {
		for _, email := range details.Emails {
			if !IsValidEmail(email) {
				return User_error_emails_invalid
			}
		}
	}

	if details.Password != nil {
		if !IsValidPassword(*details.Password) {
			return User_error_password_invalid
		}
	}

	if details.Roles != nil {
		for _, role := range details.Roles {
			if !IsValidRole(role) {
				return User_error_roles_invalid
			}
		}
	}

	if details.TermsAccepted != nil {
		if !IsValidTimestamp(*details.TermsAccepted) {
			return User_error_terms_accepted_invalid
		}
	}

	return nil
}

func ParseUpdateUserDetails(reader io.Reader) (*UpdateUserDetails, error) {
	details := &UpdateUserDetails{}
	if err := details.ExtractFromJSON(reader); err != nil {
		return nil, err
	} else {
		return details, nil
	}
}

func (u *User) IsDeleted() bool {
	return u.DeletedTime != ""
}

func (u *User) Email() string {
	return u.Username
}

func (u *User) HasRole(role string) bool {
	for _, userRole := range u.Roles {
		if userRole == role {
			return true
		}
	}
	return false
}

func (u *User) IsClinic() bool {
	return u.HasRole("clinic")
}

func (u *User) HashPassword(pw, salt string) error {
	if passwordHash, err := GeneratePasswordHash(u.Id, pw, salt); err != nil {
		return err
	} else {
		u.PwHash = passwordHash
		return nil
	}
}

func (u *User) PasswordsMatch(pw, salt string) bool {
	if u.PwHash == "" || pw == "" {
		return false
	} else if pwMatch, err := GeneratePasswordHash(u.Id, pw, salt); err != nil {
		return false
	} else {
		return u.PwHash == pwMatch
	}
}

func (u *User) IsEmailVerified(secret string) bool {
	if secret != "" {
		if strings.Contains(u.Username, secret) {
			return true
		}
		for i := range u.Emails {
			if strings.Contains(u.Emails[i], secret) {
				return true
			}
		}
	}
	return u.EmailVerified
}

func (u *User) DeepClone() *User {
	clonedUser := &User{
		Id:            u.Id,
		Username:      u.Username,
		TermsAccepted: u.TermsAccepted,
		EmailVerified: u.EmailVerified,
		PwHash:        u.PwHash,
		Hash:          u.Hash,
	}
	if u.Emails != nil {
		clonedUser.Emails = make([]string, len(u.Emails))
		copy(clonedUser.Emails, u.Emails)
	}
	if u.Roles != nil {
		clonedUser.Roles = make([]string, len(u.Roles))
		copy(clonedUser.Roles, u.Roles)
	}
	if u.Private != nil {
		clonedUser.Private = make(map[string]*IdHashPair)
		for k, v := range u.Private {
			clonedUser.Private[k] = &IdHashPair{Id: v.Id, Hash: v.Hash}
		}
	}
	if u.FailedLogin != nil {
		clonedUser.FailedLogin = &FailedLoginInfos{
			Count:                u.FailedLogin.Count,
			Total:                u.FailedLogin.Total,
			NextLoginAttemptTime: u.FailedLogin.NextLoginAttemptTime,
		}
	}
	return clonedUser
}

// CanPerformALogin check if the user can do a login
func (u *User) CanPerformALogin(maxFailedLogin int) bool {
	if u.FailedLogin == nil {
		return true
	}
	if u.FailedLogin.Count < maxFailedLogin {
		return true
	}

	now := time.Now().Format(time.RFC3339)
	if u.FailedLogin.NextLoginAttemptTime < now {
		return true
	}

	return false
}
