package user

type FindUsersResponse struct {
	Users []*User
	Error error
}

type FindUserResponse struct {
	User  *User
	Error error
}

type FindTokenResponse struct {
	SessionToken *SessionToken
	Error        error
}

type ResponsableMockStoreClient struct {
	PingResponses        []error
	UpsertUserResponses  []error
	FindUsersResponses   []FindUsersResponse
	FindUserResponses    []FindUserResponse
	RemoveUserResponses  []error
	AddTokenResponses    []error
	FindTokenResponses   []FindTokenResponse
	RemoveTokenResponses []error
}

func NewResponsableMockStoreClient() *ResponsableMockStoreClient {
	return &ResponsableMockStoreClient{}
}

func (r *ResponsableMockStoreClient) HasResponses() bool {
	return len(r.PingResponses) > 0 ||
		len(r.UpsertUserResponses) > 0 ||
		len(r.FindUsersResponses) > 0 ||
		len(r.FindUserResponses) > 0 ||
		len(r.RemoveUserResponses) > 0 ||
		len(r.AddTokenResponses) > 0 ||
		len(r.FindTokenResponses) > 0 ||
		len(r.RemoveTokenResponses) > 0
}

func (r *ResponsableMockStoreClient) Reset() {
	r.PingResponses = nil
	r.UpsertUserResponses = nil
	r.FindUsersResponses = nil
	r.FindUserResponses = nil
	r.RemoveUserResponses = nil
	r.AddTokenResponses = nil
	r.FindTokenResponses = nil
	r.RemoveTokenResponses = nil
}

func (r *ResponsableMockStoreClient) Close() {
}

func (r *ResponsableMockStoreClient) Ping() (err error) {
	if len(r.PingResponses) > 0 {
		err, r.PingResponses = r.PingResponses[0], r.PingResponses[1:]
		return
	}
	panic("PingResponses unavailable")
}

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

func (r *ResponsableMockStoreClient) FindToken(token *SessionToken) (*SessionToken, error) {
	if len(r.FindTokenResponses) > 0 {
		var response FindTokenResponse
		response, r.FindTokenResponses = r.FindTokenResponses[0], r.FindTokenResponses[1:]
		return response.SessionToken, response.Error
	}
	panic("FindTokenResponses unavailable")
}

func (r *ResponsableMockStoreClient) RemoveToken(token *SessionToken) (err error) {
	if len(r.RemoveTokenResponses) > 0 {
		err, r.RemoveTokenResponses = r.RemoveTokenResponses[0], r.RemoveTokenResponses[1:]
		return err
	}
	panic("RemoveTokenResponses unavailable")
}
