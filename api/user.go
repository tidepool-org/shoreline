package api

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

type User struct {
	id     string
	name   string
	emails []string
	pwhash string
	hash   string
}

func NewUser(name string, emails []string) *User {
	return &User{name: name, emails: emails}
}

func (u *User) HasIdentifier() bool {
	return u.name != "" || u.id != "" || len(u.emails) > 0
}

func (u *User) HashPassword(pw, salt string) error {

	if pw == "" || salt == "" {
		return errors.New("both the pw and salt are required")
	}

	hash := sha1.New()
	hash.Write([]byte(pw))
	hash.Write([]byte(salt))
	hash.Write([]byte(u.id))
	u.pwhash = hex.EncodeToString(hash.Sum(nil))

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
