package clients

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/smtp"
)

type (
	EmailNotifier struct {
		Config EmailNotifierConfig
		Auth   smtp.Auth
	}
	EmailNotifierConfig struct {
		Password string `json:"password"`
		Username string `json:"username"`
		Host     string `json:"host"`
		Port     string `json:"port"`
	}
)

func NewEmailNotifier(configSource string) *EmailNotifier {

	if jsonConfig, err := ioutil.ReadFile(configSource); err == nil {

		config := configure(jsonConfig)

		return &EmailNotifier{
			Config: config,
			Auth:   smtp.PlainAuth("", config.Username, config.Password, config.Host),
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

	address := fmt.Sprintf("%v:%v", c.Config.Host, c.Config.Port)

	//  build our message
	body := []byte("Subject: " + subject + "\r\n\r\n" + msg)

	err := smtp.SendMail(
		address,
		c.Auth,
		c.Config.Username,
		to,
		body,
	)
	if err != nil {
		return err
	}

	return nil
}
