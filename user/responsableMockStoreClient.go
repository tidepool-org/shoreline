package user

import "go.mongodb.org/mongo-driver/mongo"

type FindUsersResponse struct {
	Users []*User
	Error error
}

type FindUsersByRoleResponse struct {
	Users []*User
	Error error
}

type FindUsersWithIdsResponse struct {
	Users []*User
	Error error
}

type FindUserResponse struct {
	User  *User
	Error error
}

type FindTokenByIDResponse struct {
	SessionToken *SessionToken
	Error        error
}

type ResponsableMockStoreClient struct {
	PingResponses             []error
	UpsertUserResponses       []error
	FindUsersResponses        []FindUsersResponse
	FindUsersByRoleResponses  []FindUsersByRoleResponse
	FindUsersWithIdsResponses []FindUsersWithIdsResponse
	FindUserResponses         []FindUserResponse
	RemoveUserResponses       []error
	AddTokenResponses         []error
	FindTokenByIDResponses    []FindTokenByIDResponse
	RemoveTokenByIDResponses  []error
}

func NewResponsableMockStoreClient() *ResponsableMockStoreClient {
	return &ResponsableMockStoreClient{}
}

func (r *ResponsableMockStoreClient) HasResponses() bool {
	return len(r.PingResponses) > 0 ||
		len(r.UpsertUserResponses) > 0 ||
		len(r.FindUsersResponses) > 0 ||
		len(r.FindUsersByRoleResponses) > 0 ||
		len(r.FindUsersWithIdsResponses) > 0 ||
		len(r.FindUserResponses) > 0 ||
		len(r.RemoveUserResponses) > 0 ||
		len(r.AddTokenResponses) > 0 ||
		len(r.FindTokenByIDResponses) > 0 ||
		len(r.RemoveTokenByIDResponses) > 0
}

func (r *ResponsableMockStoreClient) Reset() {
	r.PingResponses = nil
	r.UpsertUserResponses = nil
	r.FindUsersResponses = nil
	r.FindUsersByRoleResponses = nil
	r.FindUsersWithIdsResponses = nil
	r.FindUserResponses = nil
	r.RemoveUserResponses = nil
	r.AddTokenResponses = nil
	r.FindTokenByIDResponses = nil
	r.RemoveTokenByIDResponses = nil
}

func (r *ResponsableMockStoreClient) Close() error {
	return nil
}

func (r *ResponsableMockStoreClient) Ping() (err error) {
	if len(r.PingResponses) > 0 {
		err, r.PingResponses = r.PingResponses[0], r.PingResponses[1:]
		return
	}
	panic("PingResponses unavailable")
}

func (r *ResponsableMockStoreClient) PingOK() bool {
	if len(r.PingResponses) > 0 {
		var err error
		err, r.PingResponses = r.PingResponses[0], r.PingResponses[1:]
		return err != nil
	}
	return false
}

func (r *ResponsableMockStoreClient) Collection(collectionName string, databaseName ...string) *mongo.Collection {
	return nil
}

func (r *ResponsableMockStoreClient) WaitUntilStarted() {}

func (r *ResponsableMockStoreClient) Start() {}

func (r *ResponsableMockStoreClient) UpsertUser(user *User) (err error) {
	if len(r.UpsertUserResponses) > 0 {
		err, r.UpsertUserResponses = r.UpsertUserResponses[0], r.UpsertUserResponses[1:]
		return err
	}
	panic("UpsertUserResponses unavailable")
}

func (r *ResponsableMockStoreClient) FindUsers(user *User) (found []*User, err error) {
	if len(r.FindUsersResponses) > 0 {
		var response FindUsersResponse
		response, r.FindUsersResponses = r.FindUsersResponses[0], r.FindUsersResponses[1:]
		return response.Users, response.Error
	}
	panic("FindUsersResponses unavailable")
}

func (r *ResponsableMockStoreClient) FindUsersByRole(role string) (found []*User, err error) {
	if len(r.FindUsersByRoleResponses) > 0 {
		var response FindUsersByRoleResponse
		response, r.FindUsersByRoleResponses = r.FindUsersByRoleResponses[0], r.FindUsersByRoleResponses[1:]
		return response.Users, response.Error
	}
	panic("FindUsersByRoleResponses unavailable")
}

func (r *ResponsableMockStoreClient) FindUsersWithIds(ids []string) (found []*User, err error) {
	if len(r.FindUsersWithIdsResponses) > 0 {
		var response FindUsersWithIdsResponse
		response, r.FindUsersWithIdsResponses = r.FindUsersWithIdsResponses[0], r.FindUsersWithIdsResponses[1:]
		return response.Users, response.Error
	}
	panic("FindUsersWithIdsResponses unavailable")
}

func (r *ResponsableMockStoreClient) FindUser(user *User) (found *User, err error) {
	if len(r.FindUserResponses) > 0 {
		var response FindUserResponse
		response, r.FindUserResponses = r.FindUserResponses[0], r.FindUserResponses[1:]
		return response.User, response.Error
	}
	panic("FindUserResponses unavailable")
}

func (r *ResponsableMockStoreClient) RemoveUser(user *User) (err error) {
	if len(r.RemoveUserResponses) > 0 {
		err, r.RemoveUserResponses = r.RemoveUserResponses[0], r.RemoveUserResponses[1:]
		return err
	}
	panic("RemoveUserResponses unavailable")
}

func (r *ResponsableMockStoreClient) AddToken(token *SessionToken) (err error) {
	if len(r.AddTokenResponses) > 0 {
		err, r.AddTokenResponses = r.AddTokenResponses[0], r.AddTokenResponses[1:]
		return err
	}
	panic("AddTokenResponses unavailable")
}

func (r *ResponsableMockStoreClient) FindTokenByID(id string) (*SessionToken, error) {
	if len(r.FindTokenByIDResponses) > 0 {
		var response FindTokenByIDResponse
		response, r.FindTokenByIDResponses = r.FindTokenByIDResponses[0], r.FindTokenByIDResponses[1:]
		return response.SessionToken, response.Error
	}
	panic("FindTokenByIDResponses unavailable")
}

func (r *ResponsableMockStoreClient) RemoveTokenByID(id string) (err error) {
	if len(r.RemoveTokenByIDResponses) > 0 {
		err, r.RemoveTokenByIDResponses = r.RemoveTokenByIDResponses[0], r.RemoveTokenByIDResponses[1:]
		return err
	}
	panic("RemoveTokenByIDResponses unavailable")
}
