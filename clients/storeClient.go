package clients

import (
	models "github.com/tidepool-org/shoreline/models"
)

type StoreClient interface {
	Close()
	UpsertUser(user *models.User) error
	FindUser(user *models.User) (*models.User, error)
	FindUsers(user *models.User) ([]*models.User, error)
	RemoveUser(user *models.User) error
	AddToken(token *models.SessionToken) error
	FindToken(token *models.SessionToken) (*models.SessionToken, error)
	RemoveToken(token *models.SessionToken) error
}
