package user

type Storage interface {
	Close()
	Ping() error
	UpsertUser(user *User) error
	FindUser(user *User) (*User, error)
	FindUsers(user *User) ([]*User, error)
	FindUsersByRole(role string) ([]*User, error)
	FindUsersWithIds(role []string) ([]*User, error)
	RemoveUser(user *User) error
	AddToken(token *SessionToken) error
	FindTokenByID(id string) (*SessionToken, error)
	RemoveTokenByID(id string) error
}
