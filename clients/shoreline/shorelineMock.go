package shoreline

import (
	"log"
	"strings"

	"github.com/mdblp/shoreline/schema"
	"github.com/mdblp/shoreline/token"
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

func (client *ShorelineMockClient) Login(username, password string) (*schema.UserData, string, error) {
	return &schema.UserData{UserID: client.UserID, Username: username, Emails: []string{username}}, client.ServerToken, nil
}

func (client *ShorelineMockClient) Signup(username, password, email string) (*schema.UserData, error) {
	return &schema.UserData{UserID: client.UserID, Username: username, Emails: []string{email}}, nil
}

func (client *ShorelineMockClient) CheckToken(tkn string) *token.TokenData {
	if client.Unauthorized {
		return nil
	}
	return &token.TokenData{UserId: client.UserID, IsServer: client.IsServer}
}

func (client *ShorelineMockClient) GetUser(userID, token string) (*schema.UserData, error) {
	if userID == "NotFound" {
		return nil, nil
	} else if userID == "WithoutPassword" {
		return &schema.UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false, Roles: []string{"patient"}}, nil
	} else if strings.Contains(strings.ToLower(userID), "clinic") || strings.Contains(strings.ToLower(userID), "hcp") {
		return &schema.UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false, Roles: []string{"hcp"}}, nil
	} else if strings.Contains(strings.ToLower(userID), "caregiver") {
		return &schema.UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false, Roles: []string{"caregiver"}}, nil
	} else {
		return &schema.UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: true, Roles: []string{"patient"}}, nil
	}
}

func (client *ShorelineMockClient) UpdateUser(userID string, userUpdate schema.UserUpdate, token string) error {
	return nil
}

//TODO: refactor methods above to use testify like bellow

func (client *ShorelineMockClient) TokenProvide() string {
	args := client.Called()
	return args.Get(0).(string)
}

func (client *ShorelineMockClient) GetUnverifiedUsers() ([]schema.UserData, error) {
	args := client.Called()
	return args.Get(0).([]schema.UserData), args.Error(1)
}

func (client *ShorelineMockClient) DeleteUser(userId string) error {
	client.Called(userId)
	return nil
}
