package auth0

import "github.com/mdblp/shoreline/schema"

type ClientInterface interface {
	GetUser(email string) (*schema.UserData, error)
	GetUserById(id string) (*schema.UserData, error)
	UpdateUser(id string, user *schema.UserUpdate) error
	GetUserInfo(authHeader string) (*schema.UserData, error)
}
