package client

import (
	"log"
	"strings"

	"github.com/stretchr/testify/mock"
)

type ShorelineMockClient struct {
	mock.Mock
	ServerToken  string
	Unauthorized bool
	UserID       string
	IsServer     bool
}

func NewMock(token string) *ShorelineMockClient {
	return &ShorelineMockClient{
		ServerToken:  token,
		Unauthorized: false,
		UserID:       "123.456.789",
		IsServer:     true,
	}
}

func (client *ShorelineMockClient) Start() error {
	log.Println("Started mock shoreline client")
	return nil
}

func (client *ShorelineMockClient) Close() {
	log.Println("Close mock shoreline client")
}

func (client *ShorelineMockClient) GetUser(userID, token string) (*UserData, error) {
	idVerified := false
	if strings.Contains(strings.ToLower(userID), "certified") {
		idVerified = true
	}
	if userID == "NotFound" {
		return nil, nil
	} else if userID == "WithoutPassword" {
		return &UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false, Roles: []string{"patient"}, IdVerified: idVerified}, nil
	} else if strings.Contains(strings.ToLower(userID), "clinic") || strings.Contains(strings.ToLower(userID), "hcp") {
		return &UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false, Roles: []string{"hcp"}, IdVerified: idVerified}, nil
	} else if strings.Contains(strings.ToLower(userID), "caregiver") {
		return &UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false, Roles: []string{"caregiver"}, IdVerified: idVerified}, nil
	} else {
		return &UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: true, Roles: []string{"patient"}, IdVerified: idVerified}, nil
	}
}

func (client *ShorelineMockClient) UpdateUser(userID string, userUpdate UserUpdate, token string) error {
	return nil
}

//TODO: refactor methods above to use testify like bellow

func (client *ShorelineMockClient) TokenProvide() string {
	args := client.Called()
	return args.Get(0).(string)
}

func (client *ShorelineMockClient) GetUnverifiedUsers(token string) ([]UserData, error) {
	args := client.Called()
	return args.Get(0).([]UserData), args.Error(1)
}

func (client *ShorelineMockClient) DeleteUser(userId string, token string) error {
	client.Called(userId)
	return nil
}
