package marketo

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
	"github.com/SpeakData/minimarketo"
	"os"
	"net/url"
)
type User interface {
	Email() string
	FirstName() string
	LastName() string
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

type manager struct {
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
	Timeout 	uint
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("marketo: config is missing")
	}
	if c.MARKETO_URL == "" {
		return errors.New("marketo: url is missing")
	}
	if c.MARKETO_Secret == "" {
		return errors.New("marketo: api key is missing")
	}
	if c.ClinicRole == "" {
		return errors.New("marketo: Clinic role is missing")
	}
	if c.PatientRole == "" {
		return errors.New("marketo: Patient role is missing")
	}
	if c.Timeout == 0 {
		return errors.New("marketo: client is missing")
	}
	return nil
}

func NewManager(logger *log.Logger, config *Config) (Manager, error) {
	if logger == nil {
		return nil, errors.New("marketo: logger is missing")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("marketo: config is not valid; %s", err)
	}
	var miniconfig = minimarketo.ClientConfig{
		ID:       config.MARKETO_ID,
		Secret:   config.MARKETO_Secret,
		Endpoint: config.MARKETO_URL, // https://XXX-XXX-XXX.mktorest.com
		Debug:    true,
		Timeout:  config.Timeout,
	}
	var client, err = minimarketo.NewClient(miniconfig) 
		if err != nil {
			log.Fatal(err)
		}
	return &manager{
		logger: logger,
		client: client,
		config: *config,
	}, nil
}

func (m *manager) CreateListMembershipForUser(newUser User) {
	if newUser == nil {
		return
	}

	go m.upsertListMembership(nil, newUser)
}

func (m *manager) UpdateListMembershipForUser(oldUser User, newUser User) {
	if oldUser == nil || newUser == nil {
		return
	}

	go m.upsertListMembership(oldUser, newUser)
}

func (m *manager) upsertListMembership(oldUser User, newUser User) {
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
	if err := m.upsertListMember(m.typeForUser(newUser), listEmail, newEmail); err != nil {
		m.logger.Printf(`ERROR: marketo failure upserting member from "%s" to "%s"; %s`, listEmail, newEmail, err)
	}
}

func (m *manager) upsertListMember(role string, listEmail string, newEmail string) error {
	path := "/rest/v1/leads.json"
	type Input struct {
		ID		  int    `json:"id"`
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
	exists, id := m.findLead(listEmail)
	data := CreateData{
		"updateOnly",
		"ID",
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
		log.Fatal(err)
	}
	if !response.Success {
		log.Fatal(response.Errors)
	}
	var createResults []minimarketo.RecordResult
	if err = json.Unmarshal(response.Result, &createResults); err != nil {
		log.Fatal(err)
	}
	for _, result := range createResults {
		fmt.Printf("%+v", result)
	}
}



func (m *manager) findLead(listEmail string)  (bool, int) {
	path := "/rest/v1/leads.json?"
	v := url.Values{
		"filterType":   {"email"},
		"filterValues": {listEmail},
		"fields":       {"email", "id"},
	}
	response, err := m.client.Get(path + v.Encode())
	if err != nil {
		log.Fatal(err)
	}
	if !response.Success {
		log.Fatal(response.Errors)
	}
	var leads []minimarketo.LeadResult
	if err = json.Unmarshal(response.Result, &leads); err != nil {
		log.Fatal(err)
	}
	if len(leads) == 0 {
		return false, -1
	}
	return true, leads[0].ID
	// for _, lead := range leads {
	// 	fmt.Printf("%+v", lead)
	// }
}

func (m *manager) typeForUser(user User) string {
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