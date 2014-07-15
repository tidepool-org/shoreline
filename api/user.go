package api

import (
	"crypto/sha1"
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
	hash.Sum([]byte(pw))
	hash.Sum([]byte(salt))
	hash.Sum([]byte(u.id))
	u.pwhash = string(hash.Sum(nil))

	return nil
}

func generateUniqueHash(strings []string, length int) (string, error) {

	if len(strings) > 0 && length > 0 {

		hash := sha1.New()

		for i := range strings {
			hash.Sum([]byte(strings[i]))
		}

		hash.Sum([]byte(strconv.FormatInt(time.Now().Unix(), 10)))
		//delay just a bit to make sure that we have move on in time
		time.Sleep(1 * time.Millisecond)
		hashString := string(hash.Sum(nil))
		return string([]rune(hashString)[0:length]), nil
	}

	return "", errors.New("both strings and length are required")

	/*
			var hash = crypto.algo.SHA1.create();
		    _.each(strings, function(s) {
		      if (s) hash.update(s);
		    });
		    hash.update(moment().valueOf().toString());  // this changes every millisecond so should give us a new value if we recur
		    var id = hash.finalize().toString().substr(0, len);
		    // we're going to delay just a bit to make sure that we overflow a moment() value
	*/

}
