package mailchimp

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

type User interface {
	Email() string
	IsClinic() bool
}

type Manager interface {
	CreateListMembershipForUser(newUser User)
	UpdateListMembershipForUser(oldUser User, newUser User)
}

type Client interface {
	Do(request *http.Request) (*http.Response, error)
}

type Config struct {
	URL            string `json:"url"`
	APIKey         string `json:"apiKey"`
	PersonalListID string `json:"personalListId"`
	ClinicListID   string `json:"clinicListId"`
}

func (c *Config) Validate() error {
	if c.URL == "" {
		return errors.New("mailchimp: url is missing")
	}
	if c.APIKey == "" {
		return errors.New("mailchimp: api key is missing")
	}
	if c.PersonalListID == "" {
		return errors.New("mailchimp: personal list id is missing")
	}
	if c.ClinicListID == "" {
		return errors.New("mailchimp: clinic list id is missing")
	}
	return nil
}

func NewManager(logger *log.Logger, client Client, config *Config) (Manager, error) {
	if logger == nil {
		return nil, errors.New("mailchimp: logger is missing")
	}
	if config == nil {
		return nil, errors.New("mailchimp: config is missing")
	}
	if client == nil {
		return nil, errors.New("mailchimp: client is missing")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("mailchimp: config is not valid; %s", err)
	}

	return &manager{
		logger: logger,
		client: client,
		config: config,
	}, nil
}

type manager struct {
	logger *log.Logger
	client Client
	config *Config
}

func (m *manager) CreateListMembershipForUser(newUser User) {
	if newUser == nil {
		return
	}

	go m.putListMembership(nil, newUser)
}

func (m *manager) UpdateListMembershipForUser(oldUser User, newUser User) {
	if oldUser == nil || newUser == nil {
		return
	}

	go m.putListMembership(oldUser, newUser)
}

func (m *manager) putListMembership(oldUser User, newUser User) {
	if matchUsers(oldUser, newUser) {
		return
	}

	newUserEmail := newUser.Email()
	if newUserEmail == "" {
		return
	}

	if oldUser == nil || oldUser.Email() == "" {
		oldUser = newUser
	}

	url := fmt.Sprintf("%s/lists/%s/members/%s", m.config.URL, m.listIDFromUser(newUser), m.memberIDFromUser(oldUser))

	body, err := json.Marshal(map[string]interface{}{"email_address": newUserEmail, "status_if_new": "subscribed"})
	if err != nil {
		m.logger.Printf(`ERROR: Mailchimp failure marshaling request body for "%s"; %s`, newUserEmail, err)
		return
	}

	request, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		m.logger.Printf(`ERROR: Mailchimp failure creating request for "%s"; %s`, newUserEmail, err)
		return
	}
	request.SetBasicAuth("tidepool-platform", m.config.APIKey)
	request.Header.Add("Content-Type", "application/json")

	response, err := m.client.Do(request)
	if err != nil {
		m.logger.Printf(`ERROR: Mailchimp failure sending request for "%s"; %s`, newUserEmail, err)
		return
	}
	if response.Body != nil {
		defer response.Body.Close()
	}

	if response.StatusCode != http.StatusOK {
		m.logger.Printf(`ERROR: Mailchimp failure sending request for "%s"; response.StatusCode == %d`, newUserEmail, response.StatusCode)
	}
}

func (m *manager) listIDFromUser(user User) string {
	if user.IsClinic() {
		return m.config.ClinicListID
	}
	return m.config.PersonalListID
}

func (m *manager) memberIDFromUser(user User) string {
	md5Sum := md5.Sum([]byte(user.Email()))
	return hex.EncodeToString(md5Sum[:])
}

func matchUsers(oldUser User, newUser User) bool {
	return oldUser != nil && newUser != nil && oldUser.Email() == newUser.Email() && oldUser.IsClinic() == newUser.IsClinic()
}
