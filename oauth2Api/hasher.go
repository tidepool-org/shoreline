package oauth2api

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
)

func GenerateHash(args ...string) (string, error) {

	if len(args) < 3 {
		return "", errors.New("we need at least three strings to create the hash")
	}

	hash := sha1.New()

	for i := range args {
		hash.Write([]byte(args[i]))
	}
	pwHash := hex.EncodeToString(hash.Sum(nil))

	return pwHash, nil
}
