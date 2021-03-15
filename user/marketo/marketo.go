package marketo

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"

	"github.com/SpeakData/minimarketo"
)

const path = "/rest/v1/leads.json?"

// User interface for Identifying user type. function located in user.go
type User interface {
	Email() string
	IsClinic() bool
}

// Manager interface for managing leads
type Manager interface {
	CreateListMembershipForUser(newUser User)
	UpdateListMembershipForUser(oldUser User, newUser User)
	IsAvailable() bool
	WaitGroup() *sync.WaitGroup
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

// RecordResult Create/update lead uses this format
type RecordResult struct {
	ID      int    `json:"id"`
	Status  string `json:"status"`
	Reasons []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"reasons,omitempty"`
}

// Input type is the request user information format sent to marketo
type Input struct {
	ID       int    `json:"id,omitempty"`
	Email    string `json:"email"`
	UserType string `json:"userType"`
	// Env		  string `json:"envType"`
}

// CreateData is the full marketo request format
type CreateData struct {
	Action      string  `json:"action"`
	LookupField string  `json:"lookupField"`
	Input       []Input `json:"input"`
}

// Connector manages the connection to the client
type Connector struct {
	logger *log.Logger
	client minimarketo.Client
	config Config
	wg     sync.WaitGroup
}

// Config is the env config
type Config struct {
	// ID: Marketo client ID
	ID string
	// Secret: Marketo client secret
	Secret string
	// Endpoint: https://xxx-xxx-xxx.mktorest.com
	URL         string
	ClinicRole  string
	PatientRole string
	Timeout     uint
}

// Validate used to validate in marketo_test.go
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("marketo: config is missing")
	}
	if c.ID == "" {
		return errors.New("marketo: ID is missing")
	}
	if c.URL == "" {
		return errors.New("marketo: url is missing")
	}
	if c.Secret == "" {
		return errors.New("marketo: secret is missing")
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

// Miniconfig handles the connection to the client through mini marketo
func Miniconfig(config Config) minimarketo.ClientConfig {
	return minimarketo.ClientConfig{
		ID:       config.ID,
		Secret:   config.Secret,
		Endpoint: config.URL, // https://XXX-XXX-XXX.mktorest.com
		Debug:    true,
		Timeout:  config.Timeout,
	}
}

// Client defines client
func Client(miniconfig minimarketo.ClientConfig) (minimarketo.Client, error) {
	client, err := minimarketo.NewClient(miniconfig)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return client, nil
}

// repairManager recreat
func (m *Connector) repairManager() {
	miniconfig := Miniconfig(m.config)
	client, _ := Client(miniconfig)
	m.client = client
}

// NewManager creates a new manager based off of input arguments
func NewManager(logger *log.Logger, config Config) (Manager, error) {
	connector := Connector{
		logger: logger,
		config: config,
	}
	if err := config.Validate(); err != nil {
		return &connector, fmt.Errorf("marketo: config is not valid; %s", err)
	}
	miniconfig := Miniconfig(config)
	client, err := Client(miniconfig)
	connector.client = client
	if err != nil {
		return &connector, err
	}
	if logger == nil {
		return &connector, errors.New("marketo: logger is missing")
	}
	if client == nil {
		return &connector, errors.New("marketo: Could not connect to marketo")
	}
	return &connector, nil
}

// WaitGroup returns the current waiting group for the connector
func (m *Connector) WaitGroup() *sync.WaitGroup {
	return &m.wg
}

// CreateListMembershipForUser is an asynchronous function that creates a user
func (m *Connector) CreateListMembershipForUser(newUser User) {
	m.logger.Printf("CreateListMembershipForUser %v", newUser)
	if newUser == nil {
		m.logger.Printf("nil user")
		return
	}
	m.wg.Add(1)
	go m.UpsertListMembership(nil, newUser)
}

// UpdateListMembershipForUser is an asynchronous function that updates a user
func (m *Connector) UpdateListMembershipForUser(oldUser User, newUser User) {
	m.logger.Printf("UpdateListMembershipForUser %v %v", oldUser, newUser)
	if oldUser == nil || newUser == nil {
		m.logger.Printf("nil user")
		return
	}
	m.wg.Add(1)
	go m.UpsertListMembership(oldUser, newUser)
}

// UpsertListMembership creates or updates a user depending on if the user already exists or not
func (m *Connector) UpsertListMembership(oldUser User, newUser User) error {
	defer m.wg.Done()
	if matchUsers(oldUser, newUser) {
		return nil
	}
	newEmail := strings.ToLower(newUser.Email())
	if newEmail == "" {
		m.logger.Printf("empty email")
		return nil
	}
	if hasTidepoolDomain(newEmail) {
		m.logger.Printf("tidepool domain email")
		return nil
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
		return err
	}
	return nil
}

// UpsertListMember creates or updates lead based on if lead already exists
func (m *Connector) UpsertListMember(role string, listEmail string, newEmail string) error {
	id, exists, err := m.FindLead(listEmail)
	if err != nil {
		return fmt.Errorf("marketo: could not find a lead %v", err)
	}
	data := CreateData{
		"updateOnly",
		"id",
		[]Input{
			{id, newEmail, role},
		},
	}
	if !exists {
		data = CreateData{
			"createOnly",
			"email",
			[]Input{
				{0, newEmail, role},
			},
		}
	}
	dataInBytes, err := json.Marshal(data)
	response, err := m.client.Post(path, dataInBytes)
	if err != nil {
		m.logger.Println(err)
		return fmt.Errorf("marketo: could not get a response %v", err)
	}
	if !response.Success {
		m.logger.Println(response.Errors)
		return fmt.Errorf("marketo: issue with request %v", response.Errors)
	}
	var createResults []minimarketo.RecordResult
	if err = json.Unmarshal(response.Result, &createResults); err != nil {
		m.logger.Println(err)
		return fmt.Errorf("marketo: could not get a response %v", err)
	}
	return nil
}

// FindLead is used to find a lead in Marketo
func (m *Connector) FindLead(listEmail string) (int, bool, error) {
	v := url.Values{
		"filterType":   {"email"},
		"filterValues": {listEmail},
		"fields":       {"email,id"},
	}
	response, err := m.client.Get(path + v.Encode())
	if err != nil {
		m.logger.Println(err)
		return -1, false, err
	}
	if !response.Success {
		m.logger.Println(response.Errors)
		return -1, false, err
	}
	var leads []LeadResult
	if err = json.Unmarshal(response.Result, &leads); err != nil {
		m.logger.Println(err)
		return -1, false, err
	}
	if len(leads) != 1 {
		return -1, false, nil
	}
	if len(leads) == 0 {
		return -1, false, nil
	}
	return leads[0].ID, true, nil
}

// TypeForUser Identifies if the user is a clinic or patient
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

// IsAvailable is a function used to test if the Parameters in connector are there and that you have a connection to marketo ready
func (m *Connector) IsAvailable() bool {
	if m.client != nil && m.logger != nil {
		return true
	}
	m.repairManager()
	return m.client != nil && m.logger != nil
}
