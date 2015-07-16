package user

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

func generateUniqueHash(strings []string, length int) (string, error) {

	//require a minimum of three pieces of info via strings
	if len(strings) < 3 {
		return "", errors.New("generateUniqueHash: at least three strings are needed")
	}
	if length <= 0 {
		return "", errors.New("generateUniqueHash: hash length is required")
	}

	hash := sha1.New()

	for i := range strings {
		hash.Write([]byte(strings[i]))
	}

	hash.Write([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	//delay just a bit to make sure that we have move on in time
	time.Sleep(1 * time.Millisecond)
	hashString := hex.EncodeToString(hash.Sum(nil))

	return string([]rune(hashString)[0:length]), nil
}

func GeneratePasswordHash(id, pw, salt string) (string, error) {

	if salt == "" || id == "" {
		return "", errors.New("id and salt are required")
	}

	hash := sha1.New()
	if pw != "" {
		hash.Write([]byte(pw))
	}
	hash.Write([]byte(salt))
	hash.Write([]byte(id))
	pwHash := hex.EncodeToString(hash.Sum(nil))

	return pwHash, nil
}
