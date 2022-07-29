package auth0

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/mdblp/shoreline/schema"
	"github.com/pkg/errors"
)

type userMetaData struct {
	Role string `json:"role,omitempty"`
}

// user structure used by Auth0 management api
type auth0User struct {
	Email         string        `json:"email,omitempty"`
	EmailVerified bool          `json:"email_verified,omitempty"`
	UserId        string        `json:"user_id,omitempty"`
	Metadata      *userMetaData `json:"user_metadata,omitempty"`
	Password      string        `json:"password,omitempty"`
	Connection    string        `json:"connection,omitempty"`
	Subject       string        `json:"sub,omitempty"`
}

// http body content received from auth0 when requesting an access token (/oauth/token)
type auth0Token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Auth0 api client object
// Used to communicate with Auth0 management api using machine credentials
type Auth0Client struct {
	// Client id, secret and url are required to establish a connection to Auth0 and get tokens
	clientId        string
	secret          string
	logger          *log.Logger
	token           string
	mut             sync.Mutex
	closed          chan chan bool // Channel to communicate that the object has been closed
	acquiringToken  bool           // flag set when the serverLoginLoop is running
	refreshInterval time.Duration  // token refresh period in nanoseconds
	baseUrl         string
	userUrl         string
	tokenUrl        string
	audience        string
}

// Create a new client from environment variables
// requires AUTH0_URL, AUTH0_SECRET and AUTH0_CLIENT_ID to be set
func NewAuth0Client(logger *log.Logger) *Auth0Client {
	auth0Url := os.Getenv("AUTH0_URL")
	auth0Secret := os.Getenv("AUTH0_SECRET")
	auth0ClientId := os.Getenv("AUTH0_CLIENT_ID")
	if auth0Url == "" || auth0Secret == "" {
		logger.Fatal("Auth0 configuration not provided")
	}
	interval, _ := time.ParseDuration("1h")
	usrUrl, err := url.Parse(auth0Url + "/api/v2/users")
	if err != nil {
		logger.Fatal("Auth0 configuration incorrect, malformed URL: ", err.Error())
	}
	tokenUrl, _ := url.Parse(auth0Url + "/oauth/token")
	audience, _ := url.Parse(auth0Url + "/api/v2/")

	return &Auth0Client{
		secret:          auth0Secret,
		clientId:        auth0ClientId,
		logger:          logger,
		refreshInterval: interval,
		baseUrl:         auth0Url,
		userUrl:         usrUrl.String(),
		tokenUrl:        tokenUrl.String(),
		audience:        audience.String(),
	}
}

// Get an auth token and initiate the token refresh loop
func (client *Auth0Client) Start() error {
	var err error
	if client.secret == "" || client.clientId == "" {
		panic("auth0Client requires a secret and ID to be set")
	}
	if err = client.serverLogin(); err != nil {
		log.Printf("Error on initial server token acquisition, [%v]", err)
		go client.serverLoginLoop(true)
	} else {
		go client.refreshTokenLoop()
	}
	return nil
}

func (client *Auth0Client) serverLoginLoop(launchRefreshTokenLoop bool) {
	var attempts int64
	waitPeriod, _ := time.ParseDuration("5s")
	client.mut.Lock()
	if client.acquiringToken {
		client.mut.Unlock()
		return
	}
	client.acquiringToken = true
	client.mut.Unlock()
	for {
		timer := time.After(waitPeriod)
		select {
		case twoWay := <-client.closed:
			twoWay <- true
			return
		case <-timer:
			err := client.serverLogin()
			if err == nil {
				log.Printf("Server token acquired successfully after %v attempts", attempts)
				client.mut.Lock()
				client.acquiringToken = false
				client.mut.Unlock()
				if launchRefreshTokenLoop {
					go client.refreshTokenLoop()
				}
				return
			} else {
				attempts++
				log.Printf("Error when getting server token (attempt %v). Error: %v", attempts, err)
			}
		}
	}
}

func (client *Auth0Client) refreshTokenLoop() {
	for {
		timer := time.After(client.refreshInterval)
		select {
		case twoWay := <-client.closed:
			twoWay <- true
			return
		case <-timer:
			client.mut.Lock()
			acquireInProgress := client.acquiringToken
			client.mut.Unlock()
			if !acquireInProgress {
				if err := client.serverLogin(); err != nil {
					log.Printf("Error on  initial server token refresh, [%v]", err)
					go client.serverLoginLoop(false)
				}
			}
		}
	}
}

//
func (client *Auth0Client) Close() {
	twoWay := make(chan bool)
	client.closed <- twoWay
	<-twoWay
	client.mut.Lock()
	acquireInProgress := client.acquiringToken
	client.mut.Unlock()
	if acquireInProgress {
		<-twoWay
	}
	client.mut.Lock()
	defer client.mut.Unlock()
	client.token = ""
}

// Get an access token from Auth0
func (client *Auth0Client) serverLogin() error {

	var loginResult auth0Token
	params := strings.Join([]string{
		"grant_type=client_credentials",
		"client_id=" + client.clientId + "",
		"client_secret=" + client.secret,
		"audience=" + client.audience,
	},
		"&")
	payload := strings.NewReader(params)
	req, _ := http.NewRequest("POST", client.tokenUrl, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.New("Error while requesting Auth0: " + err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("Error while requesting Auth0: " + res.Status)
	}
	if err := json.NewDecoder(res.Body).Decode(&loginResult); err != nil {
		return err
	}

	client.mut.Lock()
	defer client.mut.Unlock()
	client.token = loginResult.AccessToken

	return nil
}

// Get user info from Auth0 using the email as key
func (client *Auth0Client) GetUser(email string) (*schema.UserData, error) {
	params := url.Values{}
	params.Add("q", "email:\""+email+"\"")
	url, _ := url.Parse(client.userUrl)
	url.RawQuery = params.Encode()
	req, _ := http.NewRequest("GET", url.String(), nil)
	req.Header.Add("authorization", "Bearer "+client.token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Failure to get a user")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("Error while requesting Auth0: " + res.Status)
	}
	var users []auth0User
	if err := json.NewDecoder(res.Body).Decode(&users); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	userId := parseAuth0Sub(users[0].UserId)
	user := &schema.UserData{
		UserID:        userId,
		Username:      users[0].Email,
		EmailVerified: users[0].EmailVerified,
		Emails:        []string{users[0].Email},
		Roles:         []string{users[0].Metadata.Role},
	}
	return user, nil
}

// Get user info from Auth0 using its user id as key
func (client *Auth0Client) GetUserById(id string) (*schema.UserData, error) {
	url, _ := url.Parse(client.userUrl + "/auth0|" + id)
	req, _ := http.NewRequest("GET", url.String(), nil)
	req.Header.Add("authorization", "Bearer "+client.token)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Failure to get a user")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("Error while requesting Auth0: " + res.Status)
	}
	var auth0User auth0User
	if err := json.NewDecoder(res.Body).Decode(&auth0User); err != nil {
		return nil, err
	}
	userId := parseAuth0Sub(auth0User.UserId)
	user := &schema.UserData{
		UserID:        userId,
		Username:      auth0User.Email,
		EmailVerified: auth0User.EmailVerified,
		Emails:        []string{auth0User.Email},
		Roles:         []string{auth0User.Metadata.Role},
	}
	return user, nil
}

// Update a user on Auth0
// Only the Email and Password can be udated for now
// Updating both email and password at the same time will throw an error (not accepted by Auth0)
func (client *Auth0Client) UpdateUser(id string, user *schema.UserUpdate) error {
	updUser := auth0User{}
	updUser.Connection = "Username-Password-Authentication"
	if user.Username != nil && *user.Username != "" {
		updUser.Email = *user.Username
	}
	if user.Password != nil && *user.Password != "" {
		updUser.Password = *user.Password
	}
	if user.Password == nil && user.Username == nil {
		return nil
	}
	jsonUser, _ := json.Marshal(updUser)
	url, _ := url.Parse(client.userUrl + "/auth0|" + id)
	req, _ := http.NewRequest("PATCH", url.String(), bytes.NewBuffer(jsonUser))
	req.Header.Add("authorization", "Bearer "+client.token)
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.New("Error while updating Auth0: " + err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("Error while updating Auth0: " + res.Status)
	}
	return nil
}

// Retrieve user information from auth0 based on its access token
func (client *Auth0Client) GetUserInfo(authHeader string) (*schema.UserData, error) {

	url, _ := url.Parse(client.baseUrl + "/userinfo")
	req, _ := http.NewRequest("GET", url.String(), nil)
	req.Header.Add("authorization", authHeader)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Failure to get a user")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("Error while requesting Auth0 userInfo: " + res.Status)
	}
	var user auth0User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		return nil, err
	}
	if user.Subject != "" {
		user.Subject = strings.Split(user.Subject, "|")[1]
	}

	resUser := &schema.UserData{
		UserID:        user.Subject,
		Username:      user.Email,
		EmailVerified: user.EmailVerified,
		Emails:        []string{user.Email},
	}
	return resUser, nil
}

// Extract the user id from the sub field which follows pattern auth0|userid
func parseAuth0Sub(userId string) string {
	sub := strings.Split(userId, "|")

	if len(sub) == 2 {
		userId = sub[1]
	}
	return userId
}
