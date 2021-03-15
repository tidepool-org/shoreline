// This is a client module to support server-side use of the Tidepool
// service called user-api.
package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"

	commonUserApi "github.com/tidepool-org/go-common/clients/shoreline"
	"github.com/tidepool-org/go-common/clients/status"
)

func extractUserData(data string) (*commonUserApi.UserData, error) {
	var ud commonUserApi.UserData

	if err := json.Unmarshal([]byte(data), &ud); err != nil {
		return nil, err
	}
	return &ud, nil
}

//Expose functionality to internal services
type UserClient struct{ userapi *Api }

func NewUserClient(api *Api) *UserClient {
	return &UserClient{userapi: api}
}

//added for completeness
func (client *UserClient) Close()       {}
func (client *UserClient) Start() error { return nil }

func (client *UserClient) Signup(username, password, email string) (*commonUserApi.UserData, error) {

	data := []byte(fmt.Sprintf(`{"username": "%s", "password": "%s","emails":["%s"]}`, username, password, email))
	request, _ := http.NewRequest("POST", "/user", bytes.NewBuffer(data))
	request.Header.Add("content-type", "application/json")

	response := httptest.NewRecorder()

	client.userapi.CreateUser(response, request)

	body, _ := ioutil.ReadAll(response.Body)

	switch response.Code {
	case http.StatusCreated:
		ud, err := extractUserData(string(body))
		if err != nil {
			return nil, err
		}

		return ud, nil
	default:
		return nil, &status.StatusError{
			Status: status.NewStatus(response.Code, "There was an issue trying to signup a new user"),
		}
	}
}

func (client *UserClient) Login(username, password string) (*commonUserApi.UserData, string, error) {

	request, _ := http.NewRequest("POST", "", nil)
	request.SetBasicAuth(username, password)
	response := httptest.NewRecorder()

	client.userapi.Login(response, request)

	body, _ := ioutil.ReadAll(response.Body)

	switch response.Code {
	case 200:
		ud, err := extractUserData(string(body))
		if err != nil {
			return nil, "", err
		}

		return ud, response.Header().Get("x-tidepool-session-token"), nil
	case 404:
		return nil, "", nil
	default:
		return nil, "", &status.StatusError{
			Status: status.NewStatus(response.Code, "Unknown response code from user api"),
		}
	}
}

func (client *UserClient) CheckToken(token string) *commonUserApi.TokenData {

	serverToken := client.TokenProvide()

	request, _ := http.NewRequest("GET", "", nil)
	request.Header.Add("x-tidepool-session-token", serverToken)
	res := httptest.NewRecorder()
	client.userapi.ServerCheckToken(res, request, map[string]string{"token": token})

	body, _ := ioutil.ReadAll(res.Body)

	switch res.Code {
	case 200:
		var td commonUserApi.TokenData

		if err := json.Unmarshal([]byte(string(body)), &td); err != nil {
			log.Printf("Error parsing JSON results [%s]", err.Error())
			return nil
		}

		return &td
	case 404:
		return nil
	default:
		log.Printf("Unknown response code[%d] from user api", res.Code)
		return nil
	}
}

func (client *UserClient) TokenProvide() string {

	request, _ := http.NewRequest("GET", "", nil)
	request.Header.Set(TP_SERVER_NAME, "shoreline")
	// Shoreline, as a Tidepool microservice, is using the default password
	request.Header.Set(TP_SERVER_SECRET, client.userapi.ApiConfig.ServerSecrets["default"])
	response := httptest.NewRecorder()

	client.userapi.ServerLogin(response, request)

	log.Print(USER_API_PREFIX, "UserClient.TokenProvide")

	return response.Header().Get(TP_SESSION_TOKEN)
}

func (client *UserClient) GetUser(userID, token string) (*commonUserApi.UserData, error) {
	return nil, nil
}

func (client *UserClient) UpdateUser(userID string, userUpdate commonUserApi.UserUpdate, token string) error {
	return nil
}
