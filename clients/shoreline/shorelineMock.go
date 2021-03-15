package shoreline

import (
	"log"
	"strings"

	"github.com/mdblp/shoreline/schema"
	"github.com/mdblp/shoreline/token"
)

type ShorelineMockClient struct {
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

func (client *ShorelineMockClient) TokenProvide() string {
	return client.ServerToken
}

func (client *ShorelineMockClient) GetUser(userID, token string) (*schema.UserData, error) {
	if userID == "NotFound" {
		return nil, nil
	} else if userID == "WithoutPassword" {
		return &schema.UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false}, nil
	} else if strings.Contains(strings.ToLower(userID), "clinic") {
		return &schema.UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: false, Roles: []string{"clinic"}}, nil
	} else {
		return &schema.UserData{UserID: userID, Username: "From Mock", Emails: []string{userID}, PasswordExists: true}, nil
	}
}

func (client *ShorelineMockClient) UpdateUser(userID string, userUpdate schema.UserUpdate, token string) error {
	return nil
}
