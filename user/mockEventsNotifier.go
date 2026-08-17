package user

import "context"

type NotifyUserUpdatedInvocation struct {
	Before User
	After  User
}

type MockEventsNotifier struct {
	NotifyUserDeletedResponses   []error
	NotifyUserCreatedResponses   []error
	NotifyUserUpdatedResponses   []error
	NotifyUserUpdatedInvocations []NotifyUserUpdatedInvocation
}

func NewMockEventsNotifier() *MockEventsNotifier {
	return &MockEventsNotifier{}
}

func (m *MockEventsNotifier) HasResponses() bool {
	return len(m.NotifyUserDeletedResponses) > 0 ||
		len(m.NotifyUserCreatedResponses) > 0 ||
		len(m.NotifyUserUpdatedResponses) > 0
}

func (m *MockEventsNotifier) Reset() {
	m.NotifyUserDeletedResponses = nil
	m.NotifyUserCreatedResponses = nil
	m.NotifyUserUpdatedResponses = nil
	m.NotifyUserUpdatedInvocations = nil
}

func (m *MockEventsNotifier) NotifyUserDeleted(ctx context.Context, user User, profile Profile) (err error) {
	if len(m.NotifyUserDeletedResponses) > 0 {
		err, m.NotifyUserDeletedResponses = m.NotifyUserDeletedResponses[0], m.NotifyUserDeletedResponses[1:]
		return err
	}
	panic("NotifyUserDeleted unavailable")
}

func (m *MockEventsNotifier) NotifyUserCreated(ctx context.Context, user User) (err error) {
	if len(m.NotifyUserCreatedResponses) > 0 {
		err, m.NotifyUserCreatedResponses = m.NotifyUserCreatedResponses[0], m.NotifyUserCreatedResponses[1:]
		return err
	}
	panic("NotifyUserCreated unavailable")
}

func (m *MockEventsNotifier) NotifyUserUpdated(ctx context.Context, before User, after User) (err error) {
	if len(m.NotifyUserUpdatedResponses) > 0 {
		m.NotifyUserUpdatedInvocations = append(m.NotifyUserUpdatedInvocations, NotifyUserUpdatedInvocation{Before: before, After: after})
		err, m.NotifyUserUpdatedResponses = m.NotifyUserUpdatedResponses[0], m.NotifyUserUpdatedResponses[1:]
		return err
	}
	panic("NotifyUserUpdated unavailable")
}

var _ EventsNotifier = &MockEventsNotifier{}
