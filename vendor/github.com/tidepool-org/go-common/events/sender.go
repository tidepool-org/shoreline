package events

import (
	"context"
	"github.com/Shopify/sarama"
	"github.com/cloudevents/sdk-go/protocol/kafka_sarama/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type EventProducer interface {
	Send(ctx context.Context, event Event) error
}

var _ EventProducer = &KafkaCloudEventsProducer{}
type KafkaCloudEventsProducer struct {
	client cloudevents.Client
	source string
}

func NewKafkaCloudEventsProducer(config *KafkaConfig) (*KafkaCloudEventsProducer, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V2_0_0_0

	sender, err := kafka_sarama.NewSender([]string{config.Broker}, saramaConfig, config.GetTopic())
	if err != nil {
		return nil, err
	}

	c, err := cloudevents.NewClient(sender, cloudevents.WithTimeNow(), cloudevents.WithUUIDs())
	if err != nil {
		return nil, err
	}

	return &KafkaCloudEventsProducer{client: c}, nil
}

func (c *KafkaCloudEventsProducer) SetSource(source string) {
	c.source = source
}

func (c *KafkaCloudEventsProducer) Send(ctx context.Context, event Event) error {
	ce, err := toCloudEvent(event, c.source)
	if err != nil {
		return err
	}

	return c.client.Send(ctx, ce)
}

func toCloudEvent(event Event, source string) (cloudevents.Event, error) {
	e := cloudevents.NewEvent()
	e.SetType(event.GetEventType())
	if err := e.SetData(cloudevents.ApplicationJSON, event); err != nil {
		return e, err
	}
	if source != "" {
		e.SetSource(source)
	}

	return e, nil
}
