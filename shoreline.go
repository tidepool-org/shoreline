// @title Shoreline API
// @version 1.2.0
// @description The purpose of this API is to provide authentication for end users and other tidepool Services
// @license.name BSD 2-Clause "Simplified" License
// @host api.android-qa.your-loops.dev
// @BasePath /auth
// @accept json
// @produce json
// @schemes https

// @securityDefinitions.basic BasicAuth
// @in header
// @name Authorization

// @securityDefinitions.apikey TidepoolAuth
// @in header
// @name x-tidepool-session-token
package main

import (
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"github.com/mdblp/shoreline/user"

	common "github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/hakken"
	"github.com/tidepool-org/go-common/clients/mongo"
)

type (
	// Config is the Shoreline main configuration
	Config struct {
		clients.Config
		Service disc.ServiceListing `json:"service"`
		Mongo   mongo.Config        `json:"mongo"`
		User    user.ApiConfig      `json:"user"`
	}
)

func main() {
	var config Config
	logger := log.New(os.Stdout, user.USER_API_PREFIX, log.LstdFlags|log.Lshortfile)
	auditLogger := log.New(os.Stdout, user.USER_API_PREFIX, log.LstdFlags)
	// Init random number generator
	rand.Seed(time.Now().UnixNano())

	// Set some default config values
	config.User.MaxFailedLogin = 5
	config.User.DelayBeforeNextLoginAttempt = 10 // 10 minutes
	config.User.MaxConcurrentLogin = 100
	config.User.BlockParallelLogin = true

	if err := common.LoadEnvironmentConfig([]string{"TIDEPOOL_SHORELINE_ENV", "TIDEPOOL_SHORELINE_SERVICE"}, &config); err != nil {
		logger.Panic("Problem loading Shoreline config", err)
	}

	// server secret may be passed via a separate env variable to accomodate easy secrets injection via Kubernetes
	// The server secret is the password any Tidepool service is supposed to know and pass to shoreline for authentication and for getting token
	// With Mdblp, we consider we can have different server secrets
	// These secrets are hosted in a map[string][string] instead of single string
	// which 1st string represents Server/Service name and 2nd represents the actual secret
	// here we consider this SERVER_SECRET that can be injected via Kubernetes is the one for the default server/service (any Tidepool service)
	serverSecret, found := os.LookupEnv("SERVER_SECRET")
	if found {
		config.User.ServerSecrets["default"] = serverSecret
	}
	// extract the list of token secrets
	config.User.TokenSecrets = make(map[string]string)
	zdkSecret, found := os.LookupEnv("ZENDESK_SECRET")
	if found {
		config.User.TokenSecrets["zendesk"] = zdkSecret
	}
	userSecret, found := os.LookupEnv("API_SECRET")
	if found {
		config.User.Secret = userSecret
		config.User.TokenSecrets["default"] = userSecret
	}

	longTermKey, found := os.LookupEnv("LONG_TERM_KEY")
	if found {
		config.User.LongTermKey = longTermKey
	}

	verificationSecret, found := os.LookupEnv("VERIFICATION_SECRET")
	if found {
		config.User.VerificationSecret = verificationSecret
	}

	salt, found := os.LookupEnv("SALT")
	if found {
		config.User.Salt = salt
	}

	config.Mongo.FromEnv()

	/*
	 * Hakken setup
	 */
	hakkenClient := hakken.NewHakkenBuilder().
		WithConfig(&config.HakkenConfig).
		Build()

	if !config.HakkenConfig.SkipHakken {
		if err := hakkenClient.Start(); err != nil {
			logger.Fatal(err)
		}
		defer hakkenClient.Close()
	} else {
		logger.Print("skipping hakken service")
	}

	rtr := mux.NewRouter()

	/*
	 * User-Api setup
	 */
	storage, err := user.NewStore(&config.Mongo, logger)
	if err != nil {
		logger.Fatal(err)
	}
	defer storage.Close()
	storage.Start()

	userapi := user.InitApi(config.User, logger, storage, auditLogger)
	logger.Print("installing handlers")
	userapi.SetHandlers("", rtr)

	/*
	 * Serve it up and publish
	 */
	done := make(chan bool)
	logger.Print("creating http server")
	server := common.NewServer(&http.Server{
		Addr:    config.Service.GetPort(),
		Handler: rtr,
	})

	var start func() error
	if config.Service.Scheme == "https" {
		sslSpec := config.Service.GetSSLSpec()
		start = func() error { return server.ListenAndServeTLS(sslSpec.CertFile, sslSpec.KeyFile) }
	} else {
		start = func() error { return server.ListenAndServe() }
	}

	logger.Print("starting http server")
	if err := start(); err != nil {
		logger.Fatal(err)
	}

	hakkenClient.Publish(&config.Service)

	logger.Print("listenting for signals")

	// Wait for SIGINT (Ctrl+C) or SIGTERM to stop the service
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			<-sigc
			storage.Close()
			server.Close()
			done <- true
		}
	}()

	<-done

}
