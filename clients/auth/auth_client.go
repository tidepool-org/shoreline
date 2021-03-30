package auth

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mdblp/shoreline/token"
)

const (
	errorNoConfig   = "config is missing"
	errorEmptyToken = "Session token is empty"
)

var unpackToken = token.UnpackSessionTokenAndVerify

// Config holds the configuration for the Auth Client
type Config struct {
	ServiceSecret string `json:"serviceSecret"`
}

type AuthService interface {
	Authenticate(sessionToken string) (*token.TokenData, error)
	AuthMiddleware(authorizeUnverified bool) gin.HandlerFunc
}

// Client holds the state of the Auth Client
type LocalAuth struct {
	config *Config
}

// NewClient creates a new Auth Client
func NewAuthService(config *Config) (*LocalAuth, error) {
	if config == nil {
		return nil, errors.New(errorNoConfig)
	}
	return &LocalAuth{
		config: config,
	}, nil
}

func (l *LocalAuth) Authenticate(sessionToken string) (*token.TokenData, error) {
	if sessionToken == "" {
		return nil, errors.New(errorEmptyToken)
	}
	tokenData, err := unpackToken(sessionToken, l.config.ServiceSecret)
	if err != nil {
		return nil, err
	}
	// should not return tokenData but a member structure?
	return tokenData, nil
}

// check tidepool session token and return a user struct if valid
func (l *LocalAuth) AuthMiddleware(authorizeUnverified bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionToken := c.Request.Header.Get(token.TP_SESSION_TOKEN)
		method := c.Request.Method
		path := c.Request.RequestURI

		if token, err := l.Authenticate(sessionToken); err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
		} else if token.Role == "unverified" && !authorizeUnverified {
			c.AbortWithError(http.StatusUnauthorized, errors.New("Unverified user is not authorized"))
		} else {
			log.Println("user ", token.UserId, " ", method, " on ", path)
			c.Set("userId", token.UserId)
			c.Set("isPatient", token.Role == "patient")
			c.Set("isCaregiver", token.Role == "caregiver")
			c.Set("isHCP", token.Role == "hcp")
			c.Set("isServer", token.IsServer)
		}

		c.Next()
	}
}
