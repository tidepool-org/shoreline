package user

import "github.com/satori/go.uuid"

type (
	AnonIdHashPair struct {
		Name string `json:"name"`
		Id   string `json:"id"`
		Hash string `json:"hash"`
	}
	IdHashPair struct {
		Id   string `json:"id"`
		Hash string `json:"hash"`
	}
)

func NewAnonIdHashPair(baseStrings []string) *AnonIdHashPair {
	//deal with extra `randomness` here rather than rely on it being provided
	baseStrings = append(baseStrings, uuid.NewV4().String(), uuid.NewV4().String())

	id, _ := generateUniqueHash(baseStrings, 10)
	hash, _ := generateUniqueHash(baseStrings, 24)

	return &AnonIdHashPair{Name: "", Id: id, Hash: hash}
}

func NewIdHashPair(baseStrings []string, params map[string][]string) *IdHashPair {

	for k, v := range params {
		baseStrings = append(baseStrings, k)
		baseStrings = append(baseStrings, v[0])
	}

	id, _ := generateUniqueHash(baseStrings, 10)
	hash, _ := generateUniqueHash(baseStrings, 24)

	return &IdHashPair{Id: id, Hash: hash}
}
