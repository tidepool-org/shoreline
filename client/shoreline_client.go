package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mdblp/go-common/v2/blperr"
	"github.com/mdblp/go-common/v2/http/request"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"github.com/mdblp/go-common/v2/clients/status"
	log "github.com/sirupsen/logrus"
)

const serverAuthErrorKind = "shoreline-connection"

type (
	Client struct {
		host           string        // host url
		httpClient     *http.Client  // store a reference to the http client so we can reuse it
		config         *ClientConfig // Configuration for the client
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
		Name                 string        `json:"name"`                 // The name of this server for use in obtaining a server token
		Secret               string        `json:"secret"`               // The secret used along with the name to obtain a server token
		TokenRefreshInterval time.Duration `json:"tokenRefreshInterval"` // The amount of time between refreshes of the server token
		TokenGetInterval     time.Duration `json:"tokenGetInterval"`     // The amount of time between attempts to get the server token
	}
)

func NewShorelineClientBuilder() *ClientBuilder {
	return &ClientBuilder{
		config: &ClientConfig{
			TokenRefreshInterval: 6 * time.Hour,
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
	b.config.TokenRefreshInterval = val
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
		panic("Shoreline requires a hostGetter to be set")
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
	if client.config.Name == "" {
		panic("shorelineClient requires a name to be set")
	}
	if client.config.Secret == "" {
		panic("shorelineClient requires a secret to be set")
	}
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
	if client.config.Name == "" {
		panic("shorelineClient requires a name to be set")
	}
	if client.config.Secret == "" {
		panic("shorelineClient requires a secret to be set")
	}

	host.Path = path.Join(host.Path, "serverlogin")

	req, _ := http.NewRequest("POST", host.String(), nil)
	req.Header.Add("x-tidepool-server-name", client.config.Name)
	req.Header.Add("x-tidepool-server-secret", client.config.Secret)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return blperr.Newf(serverAuthErrorKind, "Failure to obtain a server token. Error = %s", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return &status.StatusError{
			Status: status.NewStatusf(res.StatusCode, "Unknown response code from service[%s]", req.URL),
		}
	}
	token := res.Header.Get(request.LegacyTokenHeader)

	client.mut.Lock()
	defer client.mut.Unlock()
	client.serverToken = token

	return nil
}

func extractUserData(r io.Reader) (*UserData, error) {
	var ud UserData
	if err := json.NewDecoder(r).Decode(&ud); err != nil {
		return nil, err
	}
	return &ud, nil
}

func extractUsersData(r io.Reader) ([]UserData, error) {
	var ud []UserData
	if err := json.NewDecoder(r).Decode(&ud); err != nil {
		return nil, err
	}
	return ud, nil
}

// Return a valid service token
func (client *Client) TokenProvide() string {
	client.mut.Lock()
	defer client.mut.Unlock()

	return client.serverToken
}

// Get users with unverified email
func (client *Client) GetUnverifiedUsers(ctx context.Context, token string) ([]UserData, error) {
	req, err := request.NewGetBuilder(client.host).
		WithPath("user").
		WithAuthToken(token).WithQueryParams(map[string]string{"emailVerified": "false"}).
		Build(ctx)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil, blperr.Newf(serverAuthErrorKind, "failure to get unverified users. Error = %v", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		ud, err := extractUsersData(res.Body)
		if err != nil {
			return nil, err
		}
		return ud, nil
	case http.StatusNoContent:
		return []UserData{}, nil
	default:
		return nil, &status.StatusError{
			Status: status.NewStatusf(res.StatusCode, "unknown response code from service[%s]", req.URL),
		}
	}
}

// Get user details for the given user (from legacy auth system)
// In this case the userID could be the actual ID or an email address
func (client *Client) GetUser(ctx context.Context, userId, token string) (*UserData, error) {
	req, err := request.NewGetBuilder(client.host).
		WithPath("user", userId).
		WithAuthToken(token).Build(ctx)

	if err != nil {
		return nil, blperr.Newf(serverAuthErrorKind, "Failure to get a user. Error = %v", err)
	}
	res, err := client.httpClient.Do(req)
	if err != nil {
		return nil, blperr.Newf(serverAuthErrorKind, "Failure to get a user. Error = %v", err)
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
		return &UserData{}, nil
	default:
		return nil, &status.StatusError{
			Status: status.NewStatusf(res.StatusCode, "Unknown response code from service[%s]", req.URL),
		}
	}
}

// Update a user in backloops legacy authentication db (shoreline)
func (client *Client) UpdateUser(ctx context.Context, userId string, userUpdate UserUpdate, token string) error {
	//structure that the update are given to us in
	type updatesToApply struct {
		Updates UserUpdate `json:"updates"`
	}

	req, err := request.NewPutBuilder(client.host).
		WithPath("user", userId).
		WithAuthToken(token).WithPayload(updatesToApply{Updates: userUpdate}).
		Build(ctx)

	if err != nil {
		return blperr.Newf(serverAuthErrorKind, "Failure to update a user. Error = %v", err)
	}

	res, err := client.httpClient.Do(req)
	if err != nil {
		return blperr.Newf(serverAuthErrorKind, "Failure to update a user. Error = %v", err)
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
