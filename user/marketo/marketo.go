package marketo

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/SpeakData/minimarketo"
)

type User interface {
	Email() string
	// FirstName() string
	// LastName() string
	IsClinic() bool
}

// Manager type for managing leads
type Manager interface {
	CreateListMembershipForUser(newUser User)
	UpdateListMembershipForUser(oldUser User, newUser User)
}

// LeadResult Find lead returns "result" in this format
type LeadResult struct {
	ID        int    `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	UserType  string `json:"userType"`
	Created   string `json:"createdAt"`
	Updated   string `json:"updatedAt"`
}

// Create/update lead uses this format
type RecordResult struct {
	ID      int    `json:"id"`
	Status  string `json:"status"`
	Reasons []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"reasons,omitempty"`
}
type Input struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	UserType  string `json:"userType"`
	// Env		  string `json:"envType"`
}
type CreateData struct {
	Action      string  `json:"action"`
	LookupField string  `json:"lookupField"`
	Input       []Input `json:"input"`
}

type Connector struct {
	logger *log.Logger
	client minimarketo.Client
	config Config
}
type Config struct {
	// ID: Marketo client ID
	MARKETO_ID string
	// Secret: Marketo client secret
	MARKETO_Secret string
	// Endpoint: https://xxx-xxx-xxx.mktorest.com
	MARKETO_URL string
	ClinicRole  string
	PatientRole string
	Timeout     uint
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("marketo: config is missing")
	}
	if c.MARKETO_ID == "" {
		return errors.New("marketo: ID is missing")
	}
	if c.MARKETO_URL == "" {
		return errors.New("marketo: url is missing")
	}
	if c.MARKETO_Secret == "" {
		return errors.New("marketo: api key is missing")
	}
	if c.ClinicRole == "" {
		return errors.New("marketo: clinic role is missing")
	}
	if c.PatientRole == "" {
		return errors.New("marketo: patient role is missing")
	}
	if c.Timeout == 0 {
		return errors.New("marketo: timeout error")
	}
	return nil
}

func Miniconfig(config Config) minimarketo.ClientConfig {
	return minimarketo.ClientConfig{
		ID:       config.MARKETO_ID,
		Secret:   config.MARKETO_Secret,
		Endpoint: config.MARKETO_URL, // https://XXX-XXX-XXX.mktorest.com
		Debug:    true,
		Timeout:  config.Timeout,
	}
}
func Client(miniconfig minimarketo.ClientConfig) (client minimarketo.Client, err error) {
	client, err = minimarketo.NewClient(miniconfig)
	if err != nil {
		log.Fatal(err)
	}
	return
}
func NewManager(logger *log.Logger, config *Config, client minimarketo.Client) (Manager, error) {
	if logger == nil {
		return nil, errors.New("marketo: logger is missing")
	}
	if client == nil {
		return nil, errors.New("marketo: client is missing")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("marketo: config is not valid; %s", err)
	}
	return &Connector{
		logger: logger,
		client: client,
		config: *config,
	}, nil
}

func (m *Connector) CreateListMembershipForUser(newUser User) {
	if newUser == nil {
		return
	}

	go m.UpsertListMembership(nil, newUser)
}

func (m *Connector) UpdateListMembershipForUser(oldUser User, newUser User) {
	if oldUser == nil || newUser == nil {
		return
	}

	go m.UpsertListMembership(oldUser, newUser)
}

func (m *Connector) UpsertListMembership(oldUser User, newUser User) {
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
	if err := m.UpsertListMember(m.TypeForUser(newUser), listEmail, newEmail); err != nil {
		m.logger.Printf(`ERROR: marketo failure upserting member from "%s" to "%s"; %s`, listEmail, newEmail, err)
	}
}

// UpsertListMember creates or updates lead based on if lead already exists
func (m *Connector) UpsertListMember(role string, listEmail string, newEmail string) error {
	path := "/rest/v1/leads.json"
	id, exists := m.FindLead(listEmail)
	data := CreateData{
		"updateOnly",
		"id",
		[]Input{
			Input{id, newEmail, "John", "Doe", role},
		},
	}
	if !exists {
		data = CreateData{
			"createOnly",
			"email",
			[]Input{
				Input{id, newEmail, "John", "Doe", role},
			},
		}
	}
	dataInBytes, err := json.Marshal(data)
	response, err := m.client.Post(path, dataInBytes)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("marketo: could not get a response %v", err)
	}
	if !response.Success {
		log.Println(response.Errors)
		return errors.New("marketo: could not get a response")
	}
	var createResults []minimarketo.RecordResult
	if err = json.Unmarshal(response.Result, &createResults); err != nil {
		log.Println(err)
		return fmt.Errorf("marketo: could not get a response %v", err)
	}
	return nil
}

func (m *Connector) FindLead(listEmail string) (int, bool) {
	path := "/rest/v1/leads.json?"
	v := url.Values{
		"filterType":   {"email"},
		"filterValues": {listEmail},
		"fields":       {"email,id"},
	}
	response, err := m.client.Get(path + v.Encode())
	if err != nil {
		log.Fatal(err)
	}
	if !response.Success {
		log.Fatal(response.Errors)
	}
	var leads []LeadResult
	if err = json.Unmarshal(response.Result, &leads); err != nil {
		log.Fatal(err)
	}
	log.Printf("FIND LEAD %v", leads)
	if len(leads) != 1 {
		return -1, false
	}
	if len(leads) == 0 {
		return -1, false
	}
	return leads[0].ID, true
	// for _, lead := range leads {
	// 	fmt.Printf("%+v", lead)
	// }
}

func (m *Connector) TypeForUser(user User) string {
	if user.IsClinic() {
		return m.config.ClinicRole
	}
	return m.config.PatientRole
}

func matchUsers(oldUser User, newUser User) bool {
	return oldUser != nil && newUser != nil && oldUser.Email() == newUser.Email() && oldUser.IsClinic() == newUser.IsClinic()
}

func hasTidepoolDomain(email string) bool {
	return strings.HasSuffix(email, "@tidepool.io") || strings.HasSuffix(email, "@tidepool.org")
}
