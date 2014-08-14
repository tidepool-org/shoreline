package clients

import (
	"encoding/json"
	"github.com/stathat/amzses"
	"io/ioutil"
	"log"
)

type (
	EmailNotifier struct {
		Config EmailNotifierConfig
	}
	EmailNotifierConfig struct {
		AccessKey string `json:"awsAccessKey"`
		SecretKey string `json:"awsSecretKey"`
		From      string `json:"fromAddress"`
	}
)

func NewEmailNotifier(configSource string) *EmailNotifier {

	if jsonConfig, err := ioutil.ReadFile(configSource); err == nil {

		config := configure(jsonConfig)

		return &EmailNotifier{
			Config: config,
		}
	} else {
		panic(err)
	}

}

func configure(jsonConfig []byte) EmailNotifierConfig {
	var config EmailNotifierConfig
	if err := json.Unmarshal(jsonConfig, &config); err != nil {
		log.Fatal(err)
	}
	return config
}

func (c *EmailNotifier) Send(to []string, subject string, msg string) error {

	for i := range to {
		amzses.SendMail(c.Config.From, to[i], subject, msg)
	}

	return nil
}
