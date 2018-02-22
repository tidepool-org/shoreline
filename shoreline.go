package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"

	common "github.com/tidepool-org/go-common"
	"github.com/tidepool-org/go-common/clients"
	"github.com/tidepool-org/go-common/clients/disc"
	"github.com/tidepool-org/go-common/clients/hakken"
	"github.com/tidepool-org/go-common/clients/highwater"
	"github.com/tidepool-org/go-common/clients/mongo"
	"github.com/tidepool-org/shoreline/user"
)

type (
	Config struct {
		clients.Config
		Service disc.ServiceListing `json:"service"`
		Mongo   mongo.Config        `json:"mongo"`
		User    user.ApiConfig      `json:"user"`
	}
)

const (
	shoreline_service_prefix = "shoreline "
)

func main() {
	var config Config

	if err := common.LoadEnvironmentConfig([]string{"TIDEPOOL_SHORELINE_ENV", "TIDEPOOL_SHORELINE_SERVICE"}, &config); err != nil {
		log.Panic("Problem loading config", err)
	}

	/*
	 * Hakken setup
	 */
	hakkenClient := hakken.NewHakkenBuilder().
		WithConfig(&config.HakkenConfig).
		Build()

	if err := hakkenClient.Start(); err != nil {
		log.Fatal(shoreline_service_prefix, err)
	}
	defer hakkenClient.Close()

	/*
	 * Clients
	 */

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: tr}

	validator, err := user.NewJWTValidator(
		user.JWTValidatorConfig{
			Auth0AccessTokenConfig: user.Auth0AccessTokenConfig{
				Auth0Domain:    os.Getenv("TIDEPOOL_SHORELINE_AUTH0_DOMAIN"),
				Auth0Audience:  os.Getenv("TIDEPOOL_SHORELINE_AUTH0_AUDIENCE"),
				Auth0PublicKey: os.Getenv("TIDEPOOL_SHORELINE_AUTH0_PUBLICKEY"),
			},
			Secret: config.User.Secret,
		},
	)

	if err != nil {
		log.Fatal(shoreline_service_prefix, err)
	}

	rtr := mux.NewRouter()

	/*
	 * User-Api setup
	 */

	log.Println(shoreline_service_prefix, "adding api/user")

	userapi := user.InitApi(config.User, user.NewMongoStoreClient(&config.Mongo), nil, validator)
	userapi.SetHandlers("", rtr)

	userClient := user.NewUserClient(userapi)

	permsClient := clients.NewGatekeeperClientBuilder().
		WithHostGetter(config.GatekeeperConfig.ToHostGetter(hakkenClient)).
		WithHttpClient(httpClient).
		WithSecretProvider(userClient).
		Build()

	log.Print(shoreline_service_prefix, "adding", "permsClient")
	userapi.AttachPerms(permsClient)

	highwater := highwater.NewHighwaterClientBuilder().
		WithHostGetter(config.HighwaterConfig.ToHostGetter(hakkenClient)).
		WithHttpClient(httpClient).
		WithConfig(&config.HighwaterConfig.HighwaterClientConfig).
		WithSecretProvider(userClient).
		Build()

	userapi.AttachMetrics(highwater)
	/*
	 * Serve it up and publish
	 */
	done := make(chan bool)
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
	if err := start(); err != nil {
		log.Fatal(shoreline_service_prefix, err)
	}

	hakkenClient.Publish(&config.Service)

	signals := make(chan os.Signal, 40)
	signal.Notify(signals)
	go func() {
		for {
			sig := <-signals
			log.Printf(shoreline_service_prefix+"Got signal [%s]", sig)

			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				server.Close()
				done <- true
			}
		}
	}()

	<-done

}
