package clients

import (
	models "github.com/tidepool-org/shoreline/models"
)

type StoreClient interface {
	AddUser(user models.User)
	UpdateUser(user models.User)
	RemoveUser(userId string)
	AddToken(token models.SessionToken)
	UpdateToken(token models.SessionToken)
	RemoveToken(token models.SessionToken)
}
