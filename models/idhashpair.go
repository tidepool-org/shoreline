package models

type (
	AnonIdHashPair struct {
		Name       string `json:"name"`
		IdHashPair IdHashPair
	}
	IdHashPair struct {
		Id   string `json:"id"`
		Hash string `json:"hash"`
	}
)

func NewAnonIdHashPair(baseStrings []string, params map[string][]string) *AnonIdHashPair {

	for k, v := range params {
		baseStrings = append(baseStrings, k)
		baseStrings = append(baseStrings, v[0])
	}

	id, _ := generateUniqueHash(baseStrings, 10)
	hash, _ := generateUniqueHash(baseStrings, 24)

	return &AnonIdHashPair{Name: "", IdHashPair: IdHashPair{Id: id, Hash: hash}}
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
