package user

import "context"

type mockEventsNotifier struct {
	NotifyUserDeletedResponses []error
	NotifyUserCreatedResponses []error
	NotifyUserUpdatedResponses []error
}

func NewMockEventsNotifier() *mockEventsNotifier {
	return &mockEventsNotifier{}
}

func (m *mockEventsNotifier) HasResponses() bool {
	return len(m.NotifyUserDeletedResponses) > 0 ||
		len(m.NotifyUserCreatedResponses) > 0 ||
		len(m.NotifyUserUpdatedResponses) > 0
}

func (m *mockEventsNotifier) Reset() {
	m.NotifyUserDeletedResponses = nil
	m.NotifyUserCreatedResponses = nil
	m.NotifyUserUpdatedResponses = nil
}

func (m *mockEventsNotifier) NotifyUserDeleted(ctx context.Context, user User, profile Profile) (err error) {
	if len(m.NotifyUserDeletedResponses) > 0 {
		err, m.NotifyUserDeletedResponses = m.NotifyUserDeletedResponses[0], m.NotifyUserDeletedResponses[1:]
		return err
	}
	panic("NotifyUserDeleted unavailable")
}

func (m *mockEventsNotifier) NotifyUserCreated(ctx context.Context, user User) (err error) {
	if len(m.NotifyUserCreatedResponses) > 0 {
		err, m.NotifyUserCreatedResponses = m.NotifyUserCreatedResponses[0], m.NotifyUserCreatedResponses[1:]
		return err
	}
	panic("NotifyUserCreated unavailable")
}

func (m *mockEventsNotifier) NotifyUserUpdated(ctx context.Context, before User, after User) (err error) {
	if len(m.NotifyUserUpdatedResponses) > 0 {
		err, m.NotifyUserUpdatedResponses = m.NotifyUserUpdatedResponses[0], m.NotifyUserUpdatedResponses[1:]
		return err
	}
	panic("NotifyUserUpdated unavailable")
}

var _ EventsNotifier = &mockEventsNotifier{}
