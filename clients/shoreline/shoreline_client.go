package shoreline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"github.com/mdblp/shoreline/schema"
	"github.com/mdblp/shoreline/token"
	"github.com/tidepool-org/go-common/clients/status"
	"github.com/tidepool-org/go-common/errors"
	"github.com/tidepool-org/go-common/jepson"
)

type (
	ClientInterface interface {
		Start() error
		Close()
		Login(username, password string) (*schema.UserData, string, error)
		Signup(username, password, email string) (*schema.UserData, error)
		CheckToken(token string) *token.TokenData
		TokenProvide() string
		GetUser(userID, token string) (*schema.UserData, error)
		UpdateUser(userID string, userUpdate schema.UserUpdate, token string) error
	}

	Client struct {
		host       string        // host url
		httpClient *http.Client  // store a reference to the http client so we can reuse it
		config     *ClientConfig // Configuration for the client

		mut            sync.Mutex
		serverToken    string         // stores the most recently received server token
		closed         chan chan bool // Channel to communicate that the object has been closed
		acquiringToken bool           // flag set when the serverLoginLoop is running
	}

	ClientBuilder struct {
		host       string        // host url
		httpClient *http.Client  // store a reference to the http client so we can reuse it
		config     *ClientConfig // Configuration for the client

	}

	ClientConfig struct {
		Name                 string          `json:"name"`                 // The name of this server for use in obtaining a server token
		Secret               string          `json:"secret"`               // The secret used along with the name to obtain a server token
		TokenRefreshInterval jepson.Duration `json:"tokenRefreshInterval"` // The amount of time between refreshes of the server token
		TokenGetInterval     time.Duration   `json:"tokenGetInterval"`     // The amount of time between attempts to get the server token
	}
)

func NewShorelineClientBuilder() *ClientBuilder {
	return &ClientBuilder{
		config: &ClientConfig{
			TokenRefreshInterval: jepson.Duration(6 * time.Hour),
		},
	}
}

// WithHost set the host
func (b *ClientBuilder) WithHost(host string) *ClientBuilder {
	b.host = host
	return b
}

// WithHTTPClient set the HTTP client
func (b *ClientBuilder) WithHTTPClient(httpClient *http.Client) *ClientBuilder {
	b.httpClient = httpClient
	return b
}

// WithName sets the name of the server (config)
func (b *ClientBuilder) WithName(val string) *ClientBuilder {
	b.config.Name = val
	return b
}

// WithSecret sets the secret (config)
func (b *ClientBuilder) WithSecret(val string) *ClientBuilder {
	b.config.Secret = val
	return b
}

// WithTokenRefreshInterval sets the duration interval for token refresh (config)
func (b *ClientBuilder) WithTokenRefreshInterval(val time.Duration) *ClientBuilder {
	b.config.TokenRefreshInterval = jepson.Duration(val)
	return b
}

// WithTokenGetInterval sets the duration interval for token initial ack (config)
func (b *ClientBuilder) WithTokenGetInterval(val time.Duration) *ClientBuilder {
	b.config.TokenGetInterval = val
	return b
}

// WithConfig sets the whole config
func (b *ClientBuilder) WithConfig(val *ClientConfig) *ClientBuilder {
	return b.WithName(val.Name).WithSecret(val.Secret).WithTokenRefreshInterval(time.Duration(val.TokenRefreshInterval)).WithTokenGetInterval(val.TokenGetInterval)
}

// Build return client from builder
func (b *ClientBuilder) Build() *Client {

	if b.host == "" {
		panic("OpaClient requires a hostGetter to be set")
	}
	if b.config.Name == "" {
		panic("shorelineClient requires a name to be set")
	}
	if b.config.Secret == "" {
		panic("shorelineClient requires a secret to be set")
	}
	if b.httpClient == nil {
		b.httpClient = http.DefaultClient
	}

	return &Client{
		httpClient: b.httpClient,
		host:       b.host,
		config:     b.config,

		closed: make(chan chan bool),
	}
}

// NewShorelineClientFromEnv read the config from the environment variables
func NewShorelineClientFromEnv(httpClient *http.Client) *Client {
	builder := NewShorelineClientBuilder()
	host, _ := os.LookupEnv("SHORELINE_HOST")
	name, _ := os.LookupEnv("SERVICE_NAME")
	secret, _ := os.LookupEnv("SERVER_SECRET")
	tokenRefreshInterval, _ := os.LookupEnv("SHORELINE_TOKEN_REFRESH_INTERVAL")
	tokenGetInterval, _ := os.LookupEnv("SHORELINE_TOKEN_GET_INTERVAL")
	tokenRefreshDuration, _ := time.ParseDuration(tokenRefreshInterval)
	tokenGetDuration, _ := time.ParseDuration(tokenGetInterval)
	return builder.WithHost(host).
		WithHTTPClient(httpClient).
		WithName(name).
		WithSecret(secret).
		WithTokenRefreshInterval(tokenRefreshDuration).
		WithTokenGetInterval(tokenGetDuration).
		Build()
}

func (client *Client) getHost() (*url.URL, error) {
	if client.host == "" {
		return nil, errors.New("No client host defined")
	}
	theURL, err := url.Parse(client.host)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse urlString[%s]", client.host)
	}
	return theURL, nil
}

// Start starts the client and makes it ready for us.  This must be done before using any of the functionality
// that requires a server token
func (client *Client) Start() error {
	var err error
	if err = client.serverLogin(); err != nil {
		log.Printf("Error on initial server token acquisition, [%v]", err)
		go client.serverLoginLoop(true)
	} else {
		go client.refreshTokenLoop()
	}
	return nil
}

func (client *Client) serverLoginLoop(launchRefreshTokenLoop bool) {
	var attempts int64
	client.mut.Lock()
	if client.acquiringToken {
		client.mut.Unlock()
		return
	}
	client.acquiringToken = true
	client.mut.Unlock()
	for {
		timer := time.After(time.Duration(client.config.TokenGetInterval))
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

func (client *Client) refreshTokenLoop() {
	for {
		timer := time.After(time.Duration(client.config.TokenRefreshInterval))
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
func (client *Client) Close() {
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
	client.serverToken = ""
}

// serverLogin issues a request to the server for a login, using the stored
// secret that was passed in on the creation of the client object. If
// successful, it stores the returned token in ServerToken.
func (client *Client) serverLogin() error {
	host, err := client.getHost()
	if err != nil {
		return errors.New("No known user-api hosts")
	}

	host.Path = path.Join(host.Path, "serverlogin")

	req, _ := http.NewRequest("POST", host.String(), nil)
	req.Header.Add("x-tidepool-server-name", client.config.Name)
	req.Header.Add("x-tidepool-server-secret", client.config.Secret)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failure to obtain a server token")
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return &status.StatusError{
			Status: status.NewStatusf(res.StatusCode, "Unknown response code from service[%s]", req.URL),
		}
	}
	token := res.Header.Get("x-tidepool-session-token")

	client.mut.Lock()
	defer client.mut.Unlock()
	client.serverToken = token

	return nil
}

func extractUserData(r io.Reader) (*schema.UserData, error) {
	var ud schema.UserData
	if err := json.NewDecoder(r).Decode(&ud); err != nil {
		return nil, err
	}
	return &ud, nil
}

// Signs up a new platfrom user
// Returns a UserData object if successful
func (client *Client) Signup(username, password, email string) (*schema.UserData, error) {
	host, err := client.getHost()
	if err != nil {
		return nil, errors.New("No known user-api hosts.")
	}

	host.Path = path.Join(host.Path, "user")
	data := []byte(fmt.Sprintf(`{"username": "%s", "password": "%s","emails":["%s"]}`, username, password, email))

	req, _ := http.NewRequest("POST", host.String(), bytes.NewBuffer(data))

	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusCreated:
		ud, err := extractUserData(res.Body)
		if err != nil {
			return nil, err
		}

		return ud, nil
	default:
		return nil, &status.StatusError{
			Status: status.NewStatus(res.StatusCode, "There was an issue trying to signup a new user"),
		}
	}
}

// Login logs in a user with a username and password. Returns a UserData object if successful
// and also stores the returned login token into ClientToken.
func (client *Client) Login(username, password string) (*schema.UserData, string, error) {
	host, err := client.getHost()
	if err != nil {
		return nil, "", errors.New("No known user-api hosts.")
	}

	host.Path = path.Join(host.Path, "login")

	req, _ := http.NewRequest("POST", host.String(), nil)
	req.SetBasicAuth(username, password)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case 200:
		ud, err := extractUserData(res.Body)
		if err != nil {
			return nil, "", err
		}

		return ud, res.Header.Get("x-tidepool-session-token"), nil
	case 404:
		return nil, "", nil
	default:
		return nil, "", &status.StatusError{
			Status: status.NewStatusf(res.StatusCode, "Unknown response code from service[%s]", req.URL),
		}
	}
}

// CheckToken tests a token with the user-api to make sure it's current;
// if so, it returns the data encoded in the token.
func (client *Client) CheckToken(tkn string) *token.TokenData {
	host, err := client.getHost()
	if err != nil {
		return nil
	}

	host.Path = path.Join(host.Path, "token", tkn)

	req, _ := http.NewRequest("GET", host.String(), nil)
	req.Header.Add("x-tidepool-session-token", client.serverToken)

	res, err := client.httpClient.Do(req)
	if err != nil {
		log.Println("Error checking token", err)
		return nil
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case 200:
		var td token.TokenData
		if err = json.NewDecoder(res.Body).Decode(&td); err != nil {
			log.Println("Error parsing JSON results", err)
			return nil
		}
		return &td
	case 404:
		return nil
	default:
		log.Printf("Unknown response code[%d] from service[%s]", res.StatusCode, req.URL)
		return nil
	}
}

func (client *Client) TokenProvide() string {
	client.mut.Lock()
	defer client.mut.Unlock()

	return client.serverToken
}

// Get user details for the given user
// In this case the userID could be the actual ID or an email address
func (client *Client) GetUser(userID, token string) (*schema.UserData, error) {
	host, err := client.getHost()
	if err != nil {
		return nil, errors.New("No known user-api hosts.")
	}

	host.Path = path.Join(host.Path, "user", userID)

	req, _ := http.NewRequest("GET", host.String(), nil)
	req.Header.Add("x-tidepool-session-token", token)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Failure to get a user")
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		ud, err := extractUserData(res.Body)
		if err != nil {
			return nil, err
		}
		return ud, nil
	case http.StatusNoContent:
		return &schema.UserData{}, nil
	default:
		return nil, &status.StatusError{
			Status: status.NewStatusf(res.StatusCode, "Unknown response code from service[%s]", req.URL),
		}
	}
}

// Get user details for the given user
// In this case the userID could be the actual ID or an email address
func (client *Client) UpdateUser(userID string, userUpdate schema.UserUpdate, token string) error {
	host, err := client.getHost()
	if err != nil {
		return errors.New("No known user-api hosts.")
	}

	//structure that the update are given to us in
	type updatesToApply struct {
		Updates schema.UserUpdate `json:"updates"`
	}

	host.Path = path.Join(host.Path, "user", userID)
	jsonUser, err := json.Marshal(updatesToApply{Updates: userUpdate})
	if err != nil {
		return &status.StatusError{
			Status: status.NewStatusf(http.StatusInternalServerError, "Error getting user updates [%s]", err.Error()),
		}
	}

	req, _ := http.NewRequest("PUT", host.String(), bytes.NewBuffer(jsonUser))
	req.Header.Add("x-tidepool-session-token", token)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failure to get a user")
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return nil
	default:
		return &status.StatusError{
			Status: status.NewStatusf(res.StatusCode, "Unknown response code from service[%s]", req.URL),
		}
	}
}
