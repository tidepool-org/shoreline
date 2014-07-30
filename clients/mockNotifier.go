package clients

import (
	"log"
)

type (
	MockNotifier struct{}
)

func NewMockNotifier() *MockNotifier {
	return &MockNotifier{}
}

func (c *MockNotifier) Send(to []string, subject string, msg string) error {
	log.Printf("Send subject[%s] with message[%s] to[%v]", subject, msg, to)
	return nil
}
