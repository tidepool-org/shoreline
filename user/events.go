package user

import (
	"context"
	"github.com/tidepool-org/go-common/clients/shoreline"
	"github.com/tidepool-org/go-common/events"
)

type EventsNotifier interface {
	NotifyUserDeleted(ctx context.Context, user User) error
	NotifyUserCreated(ctx context.Context, user User) error
	NotifyUserUpdated(ctx context.Context, before User, after User) error
}

var _ EventsNotifier = &userEventsNotifier{}
type userEventsNotifier struct {
	events.EventProducer
}

func NewUserEventsNotifier() (EventsNotifier, error) {
	config := &events.KafkaConfig{}
	if err := config.LoadFromEnv(); err != nil {
		return nil, err
	}
	producer, err := events.NewKafkaCloudEventsProducer(config)
	if err != nil {
		return nil, err
	}
	producer.SetSource("shoreline")

	return &userEventsNotifier{
		EventProducer: producer,
	}, nil
}

func (u *userEventsNotifier) NotifyUserDeleted(ctx context.Context, user User) error {
	return u.Send(ctx, &events.DeleteUserEventPayload{
		UserData: toUserData(user),
	})
}

func (u *userEventsNotifier) NotifyUserCreated(ctx context.Context, user User) error {
	return u.Send(ctx, &events.CreateUserEventPayload{
		UserData: toUserData(user),
	})
}

func (u *userEventsNotifier) NotifyUserUpdated(ctx context.Context, before User, after User) error {
	return u.Send(ctx, &events.UpdateUserEventPayload{
		Original: toUserData(before),
		Updated: toUserData(after),
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
