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

func NewAnonIdHashPair(baseStrings []string) (*AnonIdHashPair, error) {
	//deal with extra `randomness` here rather than rely on it being provided
	baseStrings = append(baseStrings, uuid.NewV4().String(), uuid.NewV4().String())

	id, err := generateUniqueHash(baseStrings, 10)
	if err != nil {
		return nil, err
	}
	hash, err := generateUniqueHash(baseStrings, 24)
	if err != nil {
		return nil, err
	}

	return &AnonIdHashPair{Name: "", Id: id, Hash: hash}, nil
}

func NewIdHashPair(baseStrings []string, params map[string][]string) (*IdHashPair, error) {

	for k, v := range params {
		baseStrings = append(baseStrings, k)
		baseStrings = append(baseStrings, v[0])
	}

	id, err := generateUniqueHash(baseStrings, 10)
	if err != nil {
		return nil, err
	}
	hash, err := generateUniqueHash(baseStrings, 24)
	if err != nil {
		return nil, err
	}

	return &IdHashPair{Id: id, Hash: hash}, nil
}
