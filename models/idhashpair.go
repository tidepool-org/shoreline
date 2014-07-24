package models

type (
	IdHashPair struct {
		Name string `json:"name"`
		Id   string `json:"id"`
		Hash string `json:"hash"`
	}
)

func NewIdHashPair(name string, theStrings []string) *IdHashPair {

	id, _ := generateUniqueHash(theStrings, 10)
	hash, _ := generateUniqueHash(theStrings, 24)

	return &IdHashPair{Name: name, Id: id, Hash: hash}
}
