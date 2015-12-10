package clients

import (
	"encoding/json"
)

type (
	GatekeeperMock struct{}
	SeagullMock    struct{}
)

//A mock of the Gatekeeper interface
func NewGatekeeperMock() *GatekeeperMock {
	return &GatekeeperMock{}
}

func (mock *GatekeeperMock) UserInGroup(userID, groupID string) (map[string]Permissions, error) {
	perms := make(map[string]Permissions)
	p := make(Permissions)
	p["userid"] = userID
	perms["root"] = p

	return perms, nil
}

func (mock *GatekeeperMock) SetPermissions(userID, groupID string, permissions Permissions) (map[string]Permissions, error) {
	perms := make(map[string]Permissions)
	permissions["userid"] = userID
	perms["root"] = permissions
	return perms, nil
}

//A mock of the Seagull interface
func NewSeagullMock() *SeagullMock {
	return &SeagullMock{}
}

func (mock *SeagullMock) GetPrivatePair(userID, hashName, token string) *PrivatePair {
	return &PrivatePair{ID: "mock.id.123", Value: "mock value"}
}

func (mock *SeagullMock) GetCollection(userID, collectionName, token string, v interface{}) error {
	json.Unmarshal([]byte(`{"Something":"anit no thing"}`), &v)
	return nil
}
