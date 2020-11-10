package user

import (
	"context"

	"github.com/tidepool-org/go-common/clients"
)

type PermissionsResponse struct {
	Permissions clients.Permissions
	Error       error
}

type UsersPermissionsResponse struct {
	UsersPermissions clients.UsersPermissions
	Error            error
}

type ResponsableMockGatekeeper struct {
	UserInGroupResponses    []PermissionsResponse
	UsersInGroupResponses   []UsersPermissionsResponse
	SetPermissionsResponses []PermissionsResponse
}

func NewResponsableMockGatekeeper() *ResponsableMockGatekeeper {
	return &ResponsableMockGatekeeper{}
}

func (c *ResponsableMockGatekeeper) HasResponses() bool {
	return len(c.UserInGroupResponses) > 0 ||
		len(c.UsersInGroupResponses) > 0 ||
		len(c.SetPermissionsResponses) > 0
}

func (c *ResponsableMockGatekeeper) Reset() {
	c.UserInGroupResponses = nil
	c.UsersInGroupResponses = nil
	c.SetPermissionsResponses = nil
}

func (c *ResponsableMockGatekeeper) UserInGroup(ctx context.Context, userID, groupID string) (clients.Permissions, error) {
	if len(c.UserInGroupResponses) > 0 {
		var response PermissionsResponse
		response, c.UserInGroupResponses = c.UserInGroupResponses[0], c.UserInGroupResponses[1:]
		return response.Permissions, response.Error
	}
	panic("UserInGroupResponses unavailable")
}

func (c *ResponsableMockGatekeeper) UsersInGroup(ctx context.Context, groupID string) (clients.UsersPermissions, error) {
	if len(c.UsersInGroupResponses) > 0 {
		var response UsersPermissionsResponse
		response, c.UsersInGroupResponses = c.UsersInGroupResponses[0], c.UsersInGroupResponses[1:]
		return response.UsersPermissions, response.Error
	}
	panic("UsersInGroupResponses unavailable")
}

func (c *ResponsableMockGatekeeper) SetPermissions(ctx context.Context, userID, groupID string, permissions clients.Permissions) (clients.Permissions, error) {
	if len(c.SetPermissionsResponses) > 0 {
		var response PermissionsResponse
		response, c.SetPermissionsResponses = c.SetPermissionsResponses[0], c.SetPermissionsResponses[1:]
		return response.Permissions, response.Error
	}
	panic("SetPermissionsResponses unavailable")
}
