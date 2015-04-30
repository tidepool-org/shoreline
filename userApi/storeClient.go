package userapi

type StoreClient interface {
	Close()
	Ping() error
	UpsertUser(user *User) error
	FindUser(user *User) (*User, error)
	FindUsers(user *User) ([]*User, error)
	RemoveUser(user *User) error
	AddToken(token *SessionToken) error
	FindToken(token *SessionToken) (*SessionToken, error)
	RemoveToken(token *SessionToken) error
}
