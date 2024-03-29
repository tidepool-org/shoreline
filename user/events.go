package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	sl "github.com/tidepool-org/go-common/clients/shoreline"
	"github.com/tidepool-org/go-common/events"
	"log"
	"time"
)

const (
	ShorelineUserEventHandlerName = "shoreline"
	RemoveUserOperationName       = "remove_mongo_user"
	RemoveUserTokensOperationName = "remove_mongo_user_tokens"
	DefaultTimeout                = time.Second * 60
)

var failedEvents = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "tidepool_shoreline_failed_events",
	Help: "The number of failures during even handling",
}, []string{"event_type", "handler_name", "operation_name"})

type EventsNotifier interface {
	NotifyUserDeleted(ctx context.Context, user User, profile Profile) error
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

func (u *userEventsNotifier) NotifyUserDeleted(ctx context.Context, user User, profile Profile) error {
	return u.Send(ctx, &events.DeleteUserEvent{
		UserData:        toUserData(user),
		ProfileFullName: profile.FullName,
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

func toUserData(user User) sl.UserData {
	return sl.UserData{
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

func (u *eventsHandler) HandleDeleteUserEvent(payload events.DeleteUserEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	
	var errs []error
	if err := u.store.WithContext(ctx).RemoveTokensForUser(payload.UserID); err != nil {
		errs = append(errs, err)
		log.Printf("Error deleteting user tokens for user %v: %v", payload.UserID, err)
		failedEvents.WithLabelValues(payload.GetEventType(), ShorelineUserEventHandlerName, RemoveUserTokensOperationName)
	}
	if err := u.store.WithContext(ctx).RemoveUser(&User{Id: payload.UserID}); err != nil {
		errs = append(errs, err)
		log.Printf("Error deleteting user %v: %v", payload.UserID, err)
		failedEvents.WithLabelValues(payload.GetEventType(), ShorelineUserEventHandlerName, RemoveUserOperationName)
	}
	if len(errs) == 1 {
		return errs[0]
	} else if len(errs) > 1 {
		return errors.New(fmt.Sprintf("multiple errors occurred while deleting user: %v", errs))
	}

	return nil
}
