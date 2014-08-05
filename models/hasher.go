package models

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

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
