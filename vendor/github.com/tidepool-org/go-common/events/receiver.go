package events

import (
	"context"
	"github.com/Shopify/sarama"
	"github.com/cloudevents/sdk-go/protocol/kafka_sarama/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type EventHandler interface {
	CanHandle(ce cloudevents.Event) bool
	Handle(ce cloudevents.Event) error
}

type EventConsumer interface {
	RegisterHandler(handler EventHandler)
	Start(ctx context.Context) error
}

var _ EventConsumer = &KafkaCloudEventsConsumer{}
type KafkaCloudEventsConsumer struct {
	client cloudevents.Client
	handlers []EventHandler
}

func NewKafkaCloudEventsConsumer(config *KafkaConfig) (*KafkaCloudEventsConsumer, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_0_0_0

	consumer, err := kafka_sarama.NewConsumer([]string{config.Broker}, saramaConfig, config.ConsumerGroup, config.GetTopic())
	if err != nil {
		return nil, err
	}

	c, err := cloudevents.NewClient(consumer, cloudevents.WithTimeNow(), cloudevents.WithUUIDs())
	if err != nil {
		return nil, err
	}

	return &KafkaCloudEventsConsumer{
		client: c,
		handlers: make([]EventHandler, 0),
	}, nil
}

func (k *KafkaCloudEventsConsumer) RegisterHandler(handler EventHandler) {
	k.handlers = append(k.handlers, handler)
}

func (k *KafkaCloudEventsConsumer) Start(ctx context.Context) error {
	return k.client.StartReceiver(ctx, k.receive)
}

func (k *KafkaCloudEventsConsumer) receive(ce cloudevents.Event) {
	for _, handler := range k.handlers {
		if handler.CanHandle(ce) {
			_ = handler.Handle(ce)
		}
	}
}
