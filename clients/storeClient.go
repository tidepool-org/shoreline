package clients

import (
	models "github.com/tidepool-org/shoreline/models"
)

type StoreClient interface {
	UpsertUser(user *models.User) error
	FindUser(user *models.User) (*models.User, error)
	RemoveUser(userId string) error
	AddToken(token *models.SessionToken) error
	FindToken(tokenId string) (*models.SessionToken, error)
	RemoveToken(tokenId string) error
}
