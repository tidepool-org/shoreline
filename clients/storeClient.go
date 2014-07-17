package clients

import (
	api "github.com/tidepool-org/shoreline/api"
)

type StoreClient interface {
	AddUser(user api.User)
	UpdateUser(user api.User)
	RemoveUser(userId string)
	AddToken(token api.SessionToken)
	UpdateToken(token api.SessionToken)
	RemoveToken(token api.SessionToken)
}
