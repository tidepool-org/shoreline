package user

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tidepool-org/go-common/clients/shoreline"
	"github.com/tidepool-org/go-common/events"
)

const (
	ShorelineUserEventHandlerName = "shoreline"
	RemoveUserOperationName       = "remove_mongo_user"
	RemoveUserTokensOperationName = "remove_mongo_user_tokens"
)

var failedEvents = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tidepool_shoreline_failed_events",
	Help: "The number of failures during even handling",
}, []string{"event_type", "handler_name", "operation_name"})

type EventsNotifier interface {
	NotifyUserDeleted(ctx context.Context, user User) error
	NotifyUserCreated(ctx context.Context, user User) error
	NotifyUserUpdated(ctx context.Context, before User, after User) error
}

var _ EventsNotifier = &userEventsNotifier{}

type userEventsNotifier struct {
	events.EventProducer
}

func NewUserEventsNotifier(config *events.CloudEventsConfig) (EventsNotifier, error) {
	producer, err := events.NewKafkaCloudEventsProducer(config)
	if err != nil {
		return nil, err
	}

	return &userEventsNotifier{
		EventProducer: producer,
	}, nil
}

func (u *userEventsNotifier) NotifyUserDeleted(ctx context.Context, user User) error {
	return u.Send(ctx, &events.DeleteUserEvent{
		UserData: toUserData(user),
	})
}

func (u *userEventsNotifier) NotifyUserCreated(ctx context.Context, user User) error {
	return u.Send(ctx, &events.CreateUserEvent{
		UserData: toUserData(user),
	})
}

func (u *userEventsNotifier) NotifyUserUpdated(ctx context.Context, before User, after User) error {
	return u.Send(ctx, &events.UpdateUserEvent{
		Original: toUserData(before),
		Updated:  toUserData(after),
	})
}

func toUserData(user User) shoreline.UserData {
	return shoreline.UserData{
		UserID:         user.Id,
		Username:       user.Username,
		Emails:         user.Emails,
		PasswordExists: user.PwHash != "",
		Roles:          user.Roles,
		EmailVerified:  user.EmailVerified,
		TermsAccepted:  user.TermsAccepted,
	}
}

type eventsHandler struct {
	events.NoopUserEventsHandler
	store Storage
}

func NewUserEventsHandler(store Storage) (events.UserEventsHandler, error) {
	return &eventsHandler{
		store: store,
	}, nil
}
