package events

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/tidepool-org/go-common/clients/shoreline"
)

const (
	DeleteUserEventType = "users:delete"
	UpdateUserEventType = "users:update"
	CreateUserEventType = "users:create"
)

type Event interface {
	GetEventType() string
}

var _ Event = DeleteUserEventPayload{}
type DeleteUserEventPayload struct {
	shoreline.UserData `json:",inline"`
}

func (d DeleteUserEventPayload) GetEventType() string {
	return DeleteUserEventType
}

var _ Event = CreateUserEventPayload{}
type CreateUserEventPayload struct {
	shoreline.UserData `json:",inline"`
}

func (d CreateUserEventPayload) GetEventType() string {
	return CreateUserEventType
}

var _ Event = UpdateUserEventPayload{}
type UpdateUserEventPayload struct {
	Original shoreline.UserData `json:"original"`
	Updated shoreline.UserData `json:"updated"`
}

func (d UpdateUserEventPayload) GetEventType() string {
	return UpdateUserEventType
}

type UserEventsHandler interface {
	HandleUpdateUserEvent(payload UpdateUserEventPayload)
	HandleCreateUserEvent(payload CreateUserEventPayload)
	HandleDeleteUserEvent(payload DeleteUserEventPayload)
}

var _ EventHandler = &DelegatingUserEventsHandler{}
type DelegatingUserEventsHandler struct {
	delegate UserEventsHandler
}

func (d *DelegatingUserEventsHandler) CanHandle(ce cloudevents.Event) bool {
	switch ce.Type() {
	case CreateUserEventType, UpdateUserEventType, DeleteUserEventType:
		return true
	default:
		return false
	}
}

func (d *DelegatingUserEventsHandler) Handle(ce cloudevents.Event) error {
	switch ce.Type() {
	case CreateUserEventType:
		payload := CreateUserEventPayload{}
		if err := ce.DataAs(&payload); err != nil {
			return err
		}
		d.delegate.HandleCreateUserEvent(payload)
	case UpdateUserEventType:
		payload := UpdateUserEventPayload{}
		if err := ce.DataAs(&payload); err != nil {
			return err
		}
		d.delegate.HandleUpdateUserEvent(payload)
	case DeleteUserEventType:
		payload := DeleteUserEventPayload{}
		if err := ce.DataAs(&payload); err != nil {
			return err
		}
		d.delegate.HandleDeleteUserEvent(payload)
	}
	return nil
}

type NoopUserEventsHandler struct {}
var _ UserEventsHandler = &NoopUserEventsHandler{}
func (d *NoopUserEventsHandler) HandleUpdateUserEvent(payload UpdateUserEventPayload) {}
func (d *NoopUserEventsHandler) HandleCreateUserEvent(payload CreateUserEventPayload) {}
func (d *NoopUserEventsHandler) HandleDeleteUserEvent(payload DeleteUserEventPayload) {}
