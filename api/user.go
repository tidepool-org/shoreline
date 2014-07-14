package api

import (
	"crypto/sha1"
	//"strconv"
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

func (u *User) HashPassword(pw, salt string) {
	hash := sha1.New()
	hash.Sum([]byte(pw))
	hash.Sum([]byte(salt))
	hash.Sum([]byte(u.id))
	u.pwhash = string(hash.Sum(nil))
}

func generateUniqueHash(strings []string, length int) []byte {

	hash := sha1.New()

	for i := range strings {
		hash.Sum([]byte(strings[i]))
	}

	//hash.Sum([]byte(strconv.FormatInt(time.Now().Unix())))
	//delay just a bit to make sure that we have move on in time
	time.Sleep(1 * time.Millisecond)
	return hash.Sum(nil)

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
