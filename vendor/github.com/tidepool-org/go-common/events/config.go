package events

import (
	"errors"
	"github.com/Shopify/sarama"
	"github.com/kelseyhightower/envconfig"
)

type CloudEventsConfig struct {
	EventSource        string   `envconfig:"CLOUD_EVENTS_SOURCE" required:"false"`
	KafkaBrokers       []string `envconfig:"KAFKA_BROKERS" required:"true"`
	KafkaConsumerGroup string   `envconfig:"KAFKA_CONSUMER_GROUP" required:"false"`
	KafkaTopic         string   `envconfig:"KAFKA_TOPIC" default:"events"`
	KafkaTopicPrefix   string   `envconfig:"KAFKA_TOPIC_PREFIX" required:"true"`
	KafkaRequireSSL    bool     `envconfig:"KAFKA_REQUIRE_SSL" required:"true"`
	KafkaVersion       string   `envconfig:"KAFKA_VERSION" required:"true"`
	SaramaConfig       *sarama.Config
}

func NewConfig() *CloudEventsConfig {
	cfg := &CloudEventsConfig{}
	cfg.SaramaConfig = sarama.NewConfig()
	cfg.SaramaConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	return cfg
}

func (k *CloudEventsConfig) LoadFromEnv() error {
	if err := envconfig.Process("", k); err != nil {
		return err
	}
	version, err := sarama.ParseKafkaVersion(k.KafkaVersion)
	if err != nil {
		return err
	}
	k.SaramaConfig.Version = version
	if k.KafkaRequireSSL {
		k.SaramaConfig.Net.TLS.Enable = true
	}
	return nil
}

func (k *CloudEventsConfig) GetPrefixedTopic() string {
	return k.KafkaTopicPrefix + k.KafkaTopic
}

func validateProducerConfig(config *CloudEventsConfig) error {
	if config.EventSource == "" {
		return errors.New("event source cannot be empty")
	}
	return nil
}

func validateConsumerConfig(config *CloudEventsConfig) error {
	if config.KafkaConsumerGroup == "" {
		return errors.New("consumer group cannot be empty")
	}
	return nil
}
