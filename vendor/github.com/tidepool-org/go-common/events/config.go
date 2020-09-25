package events

import "github.com/kelseyhightower/envconfig"

type KafkaConfig struct {
	Broker        string `envconfig:"KAFKA_BROKERS" required:"false"`
	Prefix        string `envconfig:"KAFKA_PREFIX" required:"false"`
	BaseTopic     string `envconfig:"KAFKA_TOPIC" default:"events"`
	ConsumerGroup string `envconfig:"KAFKA_CONSUMER_GROUP" required:"false"`
}

func (k *KafkaConfig) LoadFromEnv() error {
	if err := envconfig.Process("", k); err != nil {
		return err
	}
	return nil
}

func (k *KafkaConfig) GetTopic() string {
	return k.Prefix + k.BaseTopic
}
