package mailchimp

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
)

type User interface {
	Email() string
	IsClinic() bool
}

type Manager interface {
	CreateListMembershipForUser(newUser User)
	UpdateListMembershipForUser(oldUser User, newUser User)
	WaitGroup() *sync.WaitGroup
}

type Client interface {
	Do(request *http.Request) (*http.Response, error)
}

type List struct {
	ID        string          `json:"id,omitempty"`
	Interests map[string]bool `json:"interests,omitempty"`
}

type Lists []*List

type Config struct {
	URL           string `json:"url,omitempty"`
	APIKey        string `json:"apiKey,omitempty"`
	ClinicLists   Lists  `json:"clinicLists,omitempty"`
	PersonalLists Lists  `json:"personalLists,omitempty"`
}

type Member struct {
	EmailAddress string          `json:"email_address,omitempty"`
	StatusIfNew  string          `json:"status_if_new,omitempty"`
	Interests    map[string]bool `json:"interests,omitempty"`
}

func (l *List) Validate() error {
	if l == nil {
		return errors.New("mailchimp: list is missing")
	}
	if l.ID == "" {
		return errors.New("mailchimp: id is missing")
	}
	for interestID := range l.Interests {
		if interestID == "" {
			return errors.New("mailchimp: interest id is missing")
		}
	}
	return nil
}

func (l Lists) Validate() error {
	if l == nil {
		return errors.New("mailchimp: lists are missing")
	}
	for _, list := range l {
		if err := list.Validate(); err != nil {
			return fmt.Errorf("mailchimp: list is not valid; %s", err)
		}
	}
	return nil
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("mailchimp: config is missing")
	}
	if c.URL == "" {
		return errors.New("mailchimp: url is missing")
	}
	if c.APIKey == "" {
		return errors.New("mailchimp: api key is missing")
	}
	if err := c.ClinicLists.Validate(); err != nil {
		return fmt.Errorf("mailchimp: clinic lists are not valid; %s", err)
	}
	if err := c.PersonalLists.Validate(); err != nil {
		return fmt.Errorf("mailchimp: personal lists are not valid; %s", err)
	}
	return nil
}

func NewManager(logger *log.Logger, client Client, config *Config) (Manager, error) {
	if logger == nil {
		return nil, errors.New("mailchimp: logger is missing")
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
	wg     sync.WaitGroup
}

func (m *manager) WaitGroup() *sync.WaitGroup {
	return &m.wg
}

func (m *manager) CreateListMembershipForUser(newUser User) {
	if newUser == nil {
		return
	}
	m.wg.Add(1)
	go m.upsertListMembership(nil, newUser)
}

func (m *manager) UpdateListMembershipForUser(oldUser User, newUser User) {
	if oldUser == nil || newUser == nil {
		return
	}
	m.wg.Add(1)
	go m.upsertListMembership(oldUser, newUser)
}

func (m *manager) upsertListMembership(oldUser User, newUser User) {
	defer m.wg.Done()
	if matchUsers(oldUser, newUser) {
		return
	}

	newEmail := strings.ToLower(newUser.Email())
	if newEmail == "" || hasTidepoolDomain(newEmail) {
		return
	}

	listEmail := ""
	if oldUser != nil {
		listEmail = strings.ToLower(oldUser.Email())
	}
	if listEmail == "" {
		listEmail = newEmail
	}

	for _, list := range m.listsForUser(newUser) {
		if err := m.upsertListMember(list, listEmail, newEmail); err != nil {
			m.logger.Printf(`ERROR: Mailchimp failure upserting member into list "%s" from "%s" to "%s"; %s`, list.ID, listEmail, newEmail, err)
		}
	}
}

func (m *manager) upsertListMember(list *List, listEmail string, newEmail string) error {
	member, err := m.getListMember(list, listEmail)
	if err != nil {
		return err
	}

	if member == nil {
		member = &Member{
			EmailAddress: newEmail,
			StatusIfNew:  "subscribed",
			Interests:    list.Interests,
		}
	} else if listEmail != newEmail {
		member.EmailAddress = newEmail
	} else {
		return nil
	}

	return m.putListMember(list, listEmail, member)
}

func (m *manager) getListMember(list *List, email string) (*Member, error) {
	request, err := http.NewRequest("GET", m.listMemberURL(list, email), nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth("tidepool-platform", m.config.APIKey)

	response, err := m.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		defer response.Body.Close()
	}

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		if response.Body != nil {
			if responseBodyBytes, err := ioutil.ReadAll(response.Body); err == nil {
				return nil, fmt.Errorf("mailchimp: unexpected response status code: %d with body %q", response.StatusCode, string(responseBodyBytes))
			}
		}
		return nil, fmt.Errorf("mailchimp: unexpected response status code: %d", response.StatusCode)
	}

	member := &Member{}
	if err = json.NewDecoder(response.Body).Decode(member); err != nil {
		return nil, err
	}

	return member, nil
}

func (m *manager) putListMember(list *List, email string, member *Member) error {
	body, err := json.Marshal(member)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("PUT", m.listMemberURL(list, email), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.SetBasicAuth("tidepool-platform", m.config.APIKey)
	request.Header.Add("Content-Type", "application/json")

	response, err := m.client.Do(request)
	if err != nil {
		return err
	}
	if response.Body != nil {
		defer response.Body.Close()
	}

	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			if responseBodyBytes, err := ioutil.ReadAll(response.Body); err == nil {
				return fmt.Errorf("mailchimp: unexpected response status code: %d with body %q", response.StatusCode, string(responseBodyBytes))
			}
		}
		return fmt.Errorf("mailchimp: unexpected response status code: %d", response.StatusCode)
	}

	return nil
}

func (m *manager) listsForUser(user User) Lists {
	if user.IsClinic() {
		return m.config.ClinicLists
	}
	return m.config.PersonalLists
}

func (m *manager) listMemberURL(list *List, email string) string {
	return fmt.Sprintf("%s/lists/%s/members/%s", m.config.URL, list.ID, m.emailHash(email))
}

func (m *manager) emailHash(email string) string {
	md5Sum := md5.Sum([]byte(email))
	return hex.EncodeToString(md5Sum[:])
}

func matchUsers(oldUser User, newUser User) bool {
	return oldUser != nil && newUser != nil && oldUser.Email() == newUser.Email() && oldUser.IsClinic() == newUser.IsClinic()
}

func hasTidepoolDomain(email string) bool {
	return strings.HasSuffix(email, "@tidepool.io") || strings.HasSuffix(email, "@tidepool.org")
}
