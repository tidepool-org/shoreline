package user

import (
	"context"
	"github.com/tidepool-org/go-common/clients/shoreline"
	"github.com/tidepool-org/go-common/events"
	"log"
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
	config := events.NewConfig()
	if err := config.LoadFromEnv(); err != nil {
		return nil, err
	}
	config.SaramaConfig.Net.TLS.Config.InsecureSkipVerify = true
	log.Println(config)

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
